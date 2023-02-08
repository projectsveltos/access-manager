/*
Copyright 2023. projectsveltos.io. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/projectsveltos/access-manager/pkg/scope"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	"github.com/projectsveltos/libsveltos/lib/deployer"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
	libsveltosset "github.com/projectsveltos/libsveltos/lib/set"
)

const (
	// deleteRequeueAfter is how long to wait before checking again to see if the cluster still has
	// children during deletion.
	deleteRequeueAfter = 20 * time.Second

	// normalRequeueAfter is how long to wait before checking again to see if the cluster can be moved
	// to ready after or workload features (for instance ingress or reporter) have failed
	normalRequeueAfter = 20 * time.Second
)

// RoleRequestReconciler reconciles a RoleRequest object
type RoleRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	ConcurrentReconciles int
	Deployer             deployer.DeployerInterface

	// key: RoleRequest; value RoleRequest Selector
	RoleRequests map[corev1.ObjectReference]libsveltosv1alpha1.Selector

	// use a Mutex to update Map as MaxConcurrentReconciles is higher than one
	Mux sync.Mutex
	// key: Referenced object; value: set of all RoleRequests referencing the resource
	ReferenceMap map[corev1.ObjectReference]*libsveltosset.Set
	// key: RoleRequest object; value: set of referenced resources
	RoleRequestReferenceMap map[corev1.ObjectReference]*libsveltosset.Set

	// key: Sveltos/CAPI Cluster; value: set of all RoleRequests for that cluster
	ClusterMap map[corev1.ObjectReference]*libsveltosset.Set
	// key: RoleRequest; value: set of Sveltos/CAPI Clusters matched
	RoleRequestClusterMap map[corev1.ObjectReference]*libsveltosset.Set

	// Reason for the maps:
	// RoleRequest references ConfigMaps/Secrets containing (Cluster)Role policies to be deployed in a Sveltos/CAPI Cluster.
	// When a ConfigMap/Secret changes, all the RoleRequests referencing it need to be reconciled.
	// In order to achieve so, RoleRequest reconciler could watch for ConfigMaps/Secrets. When a ConfigMap/Secret spec changes,
	// find all the RoleRequests currently referencing it and reconcile those. Problem is no I/O should be present inside a MapFunc
	// (given a ConfigMap/Secret, return all the RoleRequests referencing such ConfigMap/Secret).
	// In the MapFunc, if the list RoleRequests operation failed, we would be unable to retry or re-enqueue the RoleRequests
	// referencing the ConfigMap/Secret that changed.
	// Instead the approach taken is following:
	// - when a RoleRequest is reconciled, update the ReferenceMap;
	// - in the MapFunc, given the ConfigMap/Secret that changed, we can immeditaly get all the RoleRequests needing a reconciliation (by
	// using the ReferenceMap);
	// - if a RoleRequest is referencing a ConfigMap/Secret but its reconciliation is still queued, when ConfigMap/Secret changes,
	// ReferenceMap won't have such RoleRequest. This is not a problem as RoleRequest reconciliation is already queued and will happen.
	//
	// The RoleRequestMap is used to update ReferenceMap. Consider following scenarios to understand the need:
	// 1. RoleRequest A references ConfigMaps 1 and 2. When reconciled, ReferenceMap will have 1 => A and 2 => A;
	// and RoleRequestMap A => 1,2
	// 2. RoleRequest A changes and now references ConfigMap 1 only. We ned to remove the entry 2 => A in ReferenceMap. But
	// when we reconcile RoleRequest we have its current version we don't have its previous version. So we use RoleRequestSummaryMap (at this
	// point value stored here corresponds to reconciliation #1. We know currently RoleRequest references ConfigMap 1 only and looking
	// at RoleRequestMap we know it used to reference ConfigMap 1 and 2. So we can remove 2 => A from ReferenceMap. Only after this
	// update, we update RoleRequestMap (so new value will be A => 1)

	// For the very same reason, the use of matching clusters map.
}

//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=rolerequests,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=rolerequests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=rolerequests/finalizers,verbs=update
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=sveltosclusters,verbs=get;watch;list
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=sveltosclusters/status,verbs=get;watch;list
//+kubebuilder:rbac:groups=cluster.x-k8s.io,resources=clusters,verbs=get;watch;list
//+kubebuilder:rbac:groups=cluster.x-k8s.io,resources=clusters/status,verbs=get;watch;list
//+kubebuilder:rbac:groups=cluster.x-k8s.io,resources=machines,verbs=get;watch;list
//+kubebuilder:rbac:groups=cluster.x-k8s.io,resources=machines/status,verbs=get;watch;list

func (r *RoleRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := ctrl.LoggerFrom(ctx)
	logger.V(logs.LogInfo).Info("Reconciling")

	// Fecth the roleRequest instance
	roleRequest := &libsveltosv1alpha1.RoleRequest{}
	if err := r.Get(ctx, req.NamespacedName, roleRequest); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		logger.Error(err, "Failed to fetch RoleRequest")
		return reconcile.Result{}, errors.Wrapf(
			err,
			"Failed to fetch RoleRequest %s",
			req.NamespacedName,
		)
	}

	roleRequestScope, err := scope.NewRoleRequestScope(scope.RoleRequestScopeParams{
		Client:         r.Client,
		Logger:         logger,
		RoleRequest:    roleRequest,
		ControllerName: "rolerequest",
	})
	if err != nil {
		logger.Error(err, "Failed to create roleRequestScope")
		return reconcile.Result{}, errors.Wrapf(
			err,
			"unable to create roleRequestScope for %s",
			req.NamespacedName,
		)
	}

	// Always close the scope when exiting this function so we can persist any ClusterSummary
	// changes.
	defer func() {
		if err := roleRequestScope.Close(ctx); err != nil {
			reterr = err
		}
	}()

	// Handle deleted clusterSummary
	if !roleRequest.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, roleRequestScope, logger)
	}

	// Handle non-deleted clusterSummary
	return r.reconcileNormal(ctx, roleRequestScope, logger)
}

func (r *RoleRequestReconciler) reconcileDelete(
	ctx context.Context,
	roleRequestScope *scope.RoleRequestScope,
	logger logr.Logger,
) (reconcile.Result, error) {

	logger.V(logs.LogInfo).Info("Reconciling ClusterSummary delete")

	// Undeploy roleRequest from all clusters where it was deployed
	f := getHandlersForFeature(libsveltosv1alpha1.FeatureRoleRequest)
	err := r.undeployRoleRequest(ctx, roleRequestScope, f, logger)
	if err != nil {
		logger.V(logs.LogInfo).Error(err, "failed to undeploy")
		return reconcile.Result{Requeue: true, RequeueAfter: deleteRequeueAfter}, nil
	}

	r.Mux.Lock()
	defer r.Mux.Unlock()

	roleRequestInfo := getKeyFromObject(r.Scheme, roleRequestScope.RoleRequest)

	// Get list of Resources referenced by roleRequest
	if v, ok := r.RoleRequestReferenceMap[*roleRequestInfo]; ok {
		resources := v.Items()
		for i := range resources {
			r.getReferenceMapForEntry(&resources[i]).Erase(roleRequestInfo)
		}
	}
	delete(r.RoleRequestReferenceMap, *roleRequestInfo)

	// Get list of clusters referenced by roleRequest
	if v, ok := r.RoleRequestClusterMap[*roleRequestInfo]; ok {
		clusters := v.Items()
		for i := range clusters {
			r.getClusterMapForEntry(&clusters[i]).Erase(roleRequestInfo)
		}
	}
	delete(r.RoleRequestClusterMap, *roleRequestInfo)

	delete(r.RoleRequests, *roleRequestInfo)

	logger.V(logs.LogInfo).Info("Removing finalizer")
	if controllerutil.ContainsFinalizer(roleRequestScope.RoleRequest, libsveltosv1alpha1.RoleRequestFinalizer) {
		if finalizersUpdated := controllerutil.RemoveFinalizer(roleRequestScope.RoleRequest,
			libsveltosv1alpha1.RoleRequestFinalizer); !finalizersUpdated {
			return reconcile.Result{}, fmt.Errorf("failed to remove finalizer")
		}
	}

	logger.V(logs.LogInfo).Info("Reconcile delete success")
	return reconcile.Result{}, nil
}

func (r *RoleRequestReconciler) reconcileNormal(
	ctx context.Context,
	roleRequestScope *scope.RoleRequestScope,
	logger logr.Logger,
) (reconcile.Result, error) {

	logger.V(logs.LogInfo).Info("Reconciling ClusterSummary")

	if !controllerutil.ContainsFinalizer(roleRequestScope.RoleRequest, libsveltosv1alpha1.RoleRequestFinalizer) {
		if err := r.addFinalizer(ctx, roleRequestScope); err != nil {
			logger.V(logs.LogInfo).Error(err, "failed to add finalizer")
			return reconcile.Result{}, err
		}
	}

	matchingCluster, err := r.getMatchingClusters(ctx, roleRequestScope)
	if err != nil {
		return reconcile.Result{}, err
	}

	roleRequestScope.SetMatchingClusterRefs(matchingCluster)

	r.updateClusterInfo(roleRequestScope)

	r.updateMaps(roleRequestScope)

	f := getHandlersForFeature(libsveltosv1alpha1.FeatureRoleRequest)
	if err := r.deployRoleRequest(ctx, roleRequestScope, f, logger); err != nil {
		logger.V(logs.LogInfo).Error(err, "failed to deploy")
		return reconcile.Result{Requeue: true, RequeueAfter: normalRequeueAfter}, nil
	}

	logger.V(logs.LogInfo).Info("Reconciling RoleRequest success")
	return reconcile.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoleRequestReconciler) SetupWithManager(mgr ctrl.Manager) (controller.Controller, error) {
	c, err := ctrl.NewControllerManagedBy(mgr).
		For(&libsveltosv1alpha1.RoleRequest{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.ConcurrentReconciles,
		}).
		Build(r)
	if err != nil {
		return nil, errors.Wrap(err, "error creating controller")
	}

	// At this point we don't know yet whether CAPI is present in the cluster.
	// Later on, in main, we detect that and if CAPI is present WatchForCAPI will be invoked.

	// When Sveltos Cluster changes (from paused to unpaused), one or more ClusterSummaries
	// need to be reconciled.
	err = c.Watch(&source.Kind{Type: &libsveltosv1alpha1.SveltosCluster{}},
		handler.EnqueueRequestsFromMapFunc(r.requeueRoleRequestForCluster),
		SveltosClusterPredicates(mgr.GetLogger().WithValues("predicate", "clusterpredicate")),
	)
	if err != nil {
		return nil, err
	}

	// When ConfigMap changes, according to ConfigMapPredicates,
	// one or more ClusterSummaries need to be reconciled.
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}},
		handler.EnqueueRequestsFromMapFunc(r.requeueRoleRequestForReference),
		ConfigMapPredicates(mgr.GetLogger().WithValues("predicate", "configmappredicate")),
	)
	if err != nil {
		return nil, err
	}

	// When Secret changes, according to SecretPredicates,
	// one or more ClusterSummaries need to be reconciled.
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}},
		handler.EnqueueRequestsFromMapFunc(r.requeueRoleRequestForReference),
		SecretPredicates(mgr.GetLogger().WithValues("predicate", "secretpredicate")),
	)

	return c, err
}

func (r *RoleRequestReconciler) WatchForCAPI(mgr ctrl.Manager, c controller.Controller) error {
	// When CAPI Cluster changes (from paused to unpaused), one or more ClusterSummaries
	// need to be reconciled.
	return c.Watch(&source.Kind{Type: &clusterv1.Cluster{}},
		handler.EnqueueRequestsFromMapFunc(r.requeueRoleRequestForCluster),
		ClusterPredicates(mgr.GetLogger().WithValues("predicate", "clusterpredicate")),
	)
}

func (r *RoleRequestReconciler) getClusterMapForEntry(entry *corev1.ObjectReference) *libsveltosset.Set {
	s := r.ClusterMap[*entry]
	if s == nil {
		s = &libsveltosset.Set{}
		r.ClusterMap[*entry] = s
	}
	return s
}

func (r *RoleRequestReconciler) getReferenceMapForEntry(entry *corev1.ObjectReference) *libsveltosset.Set {
	s := r.ReferenceMap[*entry]
	if s == nil {
		s = &libsveltosset.Set{}
		r.ReferenceMap[*entry] = s
	}
	return s
}

func (r *RoleRequestReconciler) addFinalizer(ctx context.Context, roleRequestScope *scope.RoleRequestScope) error {
	// If the SveltosCluster doesn't have our finalizer, add it.
	controllerutil.AddFinalizer(roleRequestScope.RoleRequest, libsveltosv1alpha1.RoleRequestFinalizer)
	// Register the finalizer immediately to avoid orphaning rolerequest resources on delete
	if err := roleRequestScope.PatchObject(ctx); err != nil {
		roleRequestScope.Error(err, "Failed to add finalizer")
		return errors.Wrapf(
			err,
			"Failed to add finalizer for %s",
			roleRequestScope.Name(),
		)
	}
	return nil
}

func (r *RoleRequestReconciler) updateMaps(roleRequestScope *scope.RoleRequestScope) {
	currentClusters := &libsveltosset.Set{}
	for i := range roleRequestScope.RoleRequest.Status.MatchingClusterRefs {
		cluster := roleRequestScope.RoleRequest.Status.MatchingClusterRefs[i]
		clusterInfo := &corev1.ObjectReference{Namespace: cluster.Namespace, Name: cluster.Name, Kind: cluster.Kind, APIVersion: cluster.APIVersion}
		currentClusters.Insert(clusterInfo)
	}

	currentReferences := r.getCurrentReferences(roleRequestScope)

	r.Mux.Lock()
	defer r.Mux.Unlock()

	roleRequestInfo := getKeyFromObject(r.Scheme, roleRequestScope.RoleRequest)
	r.RoleRequests[*roleRequestInfo] = roleRequestScope.RoleRequest.Spec.ClusterSelector
	r.updateClusterMaps(roleRequestScope, currentClusters)
	r.updateReferenceMaps(roleRequestScope, currentReferences)
}

func (r *RoleRequestReconciler) updateClusterMaps(roleRequestScope *scope.RoleRequestScope,
	currentClusters *libsveltosset.Set) {

	roleRequestInfo := getKeyFromObject(r.Scheme, roleRequestScope.RoleRequest)

	// Get list of Clusters not matched anymore by RoleRequest
	var toBeRemoved []corev1.ObjectReference
	if v, ok := r.RoleRequestClusterMap[*roleRequestInfo]; ok {
		toBeRemoved = v.Difference(currentClusters)
	}

	// For each currently matching Cluster, add RoleRequest as consumer
	for i := range roleRequestScope.RoleRequest.Status.MatchingClusterRefs {
		cluster := roleRequestScope.RoleRequest.Status.MatchingClusterRefs[i]
		clusterInfo := &corev1.ObjectReference{Namespace: cluster.Namespace, Name: cluster.Name, Kind: cluster.Kind, APIVersion: cluster.APIVersion}
		r.getClusterMapForEntry(clusterInfo).Insert(roleRequestInfo)
	}

	// For each Cluster not matched anymore, remove RoleRequest as consumer
	for i := range toBeRemoved {
		clusterName := toBeRemoved[i]
		r.getClusterMapForEntry(&clusterName).Erase(roleRequestInfo)
	}

	// Update list of Clusters currently referenced by RoleRequest
	r.RoleRequestClusterMap[*roleRequestInfo] = currentClusters
}

func (r *RoleRequestReconciler) updateReferenceMaps(roleRequestScope *scope.RoleRequestScope,
	currentReferences *libsveltosset.Set) {

	roleRequestInfo := getKeyFromObject(r.Scheme, roleRequestScope.RoleRequest)

	// Get list of References not referenced anymore by RoleRequest
	var toBeRemoved []corev1.ObjectReference
	if v, ok := r.RoleRequestReferenceMap[*roleRequestInfo]; ok {
		toBeRemoved = v.Difference(currentReferences)
	}

	// For each currently referenced instance, add RoleRequest as consumer
	for _, referencedResource := range currentReferences.Items() {
		tmpResource := referencedResource
		r.getReferenceMapForEntry(&tmpResource).Insert(
			&corev1.ObjectReference{
				APIVersion: libsveltosv1alpha1.GroupVersion.String(),
				Kind:       libsveltosv1alpha1.RoleRequestKind,
				Name:       roleRequestScope.Name(),
			},
		)
	}

	// For each resource not reference anymore, remove RoleRequest as consumer
	for i := range toBeRemoved {
		referencedResource := toBeRemoved[i]
		r.getReferenceMapForEntry(&referencedResource).Erase(
			&corev1.ObjectReference{
				APIVersion: libsveltosv1alpha1.GroupVersion.String(),
				Kind:       libsveltosv1alpha1.RoleRequestKind,
				Name:       roleRequestScope.Name(),
			},
		)
	}

	// Update list of Clusters currently referenced by RoleRequest
	r.RoleRequestReferenceMap[*roleRequestInfo] = currentReferences
}

func (r *RoleRequestReconciler) getCurrentReferences(roleRequestScope *scope.RoleRequestScope) *libsveltosset.Set {
	currentReferences := &libsveltosset.Set{}
	for i := range roleRequestScope.RoleRequest.Spec.RoleRefs {
		referencedNamespace := roleRequestScope.RoleRequest.Spec.RoleRefs[i].Namespace
		referencedName := roleRequestScope.RoleRequest.Spec.RoleRefs[i].Name
		currentReferences.Insert(&corev1.ObjectReference{
			APIVersion: corev1.SchemeGroupVersion.String(), // the only resources that can be referenced are Secret and ConfigMap
			Kind:       roleRequestScope.RoleRequest.Spec.RoleRefs[i].Kind,
			// namespace can be set or empty. If empty the resource will
			// be searched in the cluster namespace at time of deployment
			Namespace: referencedNamespace,
			Name:      referencedName,
		})
	}
	return currentReferences
}

// getMatchingClusters returns all Sveltos/CAPI Clusters currently matching RoleRequest.Spec.ClusterSelector
func (r *RoleRequestReconciler) getMatchingClusters(ctx context.Context, roleRequestScope *scope.RoleRequestScope,
) ([]corev1.ObjectReference, error) {

	matching := make([]corev1.ObjectReference, 0)

	parsedSelector, _ := labels.Parse(roleRequestScope.GetSelector())

	tmpMatching, err := r.getMatchingCAPIClusters(ctx, roleRequestScope, parsedSelector)
	if err != nil {
		return nil, err
	}

	matching = append(matching, tmpMatching...)

	tmpMatching, err = r.getMatchingSveltosClusters(ctx, roleRequestScope, parsedSelector)
	if err != nil {
		return nil, err
	}

	matching = append(matching, tmpMatching...)

	return matching, nil
}

func (r *RoleRequestReconciler) getMatchingCAPIClusters(ctx context.Context, roleRequestScope *scope.RoleRequestScope,
	parsedSelector labels.Selector) ([]corev1.ObjectReference, error) {

	clusterList := &clusterv1.ClusterList{}
	if err := r.List(ctx, clusterList); err != nil {
		roleRequestScope.Logger.Error(err, "failed to list all Cluster")
		return nil, err
	}

	matching := make([]corev1.ObjectReference, 0)

	for i := range clusterList.Items {
		cluster := &clusterList.Items[i]

		if !cluster.DeletionTimestamp.IsZero() {
			// Only existing cluster can match
			continue
		}

		addTypeInformationToObject(r.Scheme, cluster)
		if parsedSelector.Matches(labels.Set(cluster.Labels)) {
			matching = append(matching, corev1.ObjectReference{
				Kind:       cluster.Kind,
				Namespace:  cluster.Namespace,
				Name:       cluster.Name,
				APIVersion: cluster.APIVersion,
			})
		}
	}

	return matching, nil
}

func (r *RoleRequestReconciler) getMatchingSveltosClusters(ctx context.Context, roleRequestScope *scope.RoleRequestScope,
	parsedSelector labels.Selector) ([]corev1.ObjectReference, error) {

	clusterList := &libsveltosv1alpha1.SveltosClusterList{}
	if err := r.List(ctx, clusterList); err != nil {
		roleRequestScope.Logger.Error(err, "failed to list all Cluster")
		return nil, err
	}

	matching := make([]corev1.ObjectReference, 0)

	for i := range clusterList.Items {
		cluster := &clusterList.Items[i]

		if !cluster.DeletionTimestamp.IsZero() {
			// Only existing cluster can match
			continue
		}

		addTypeInformationToObject(r.Scheme, cluster)
		if parsedSelector.Matches(labels.Set(cluster.Labels)) {
			matching = append(matching, corev1.ObjectReference{
				Kind:       cluster.Kind,
				Namespace:  cluster.Namespace,
				Name:       cluster.Name,
				APIVersion: cluster.APIVersion,
			})
		}
	}

	return matching, nil
}

// updateClusterInfo updates RoleRequest Status ClusterInfo by adding an entry for any
// new cluster where RoleRequest needs to be deployed
func (r *RoleRequestReconciler) updateClusterInfo(roleRequestScope *scope.RoleRequestScope) {
	roleRequest := roleRequestScope.RoleRequest

	getClusterID := func(cluster corev1.ObjectReference) string {
		return fmt.Sprintf("%s:%s/%s", getClusterType(&cluster), cluster.Namespace, cluster.Name)
	}

	matchingCluster := roleRequest.Status.MatchingClusterRefs

	// Build Map for all Clusters with an entry in Classifier.Status.ClusterInfo
	clusterMap := make(map[string]bool)
	for i := range roleRequest.Status.ClusterInfo {
		c := &roleRequest.Status.ClusterInfo[i]
		clusterMap[getClusterID(c.Cluster)] = true
	}

	newClusterInfo := make([]libsveltosv1alpha1.ClusterInfo, 0)
	for i := range matchingCluster {
		c := matchingCluster[i]
		if _, ok := clusterMap[getClusterID(c)]; !ok {
			newClusterInfo = append(newClusterInfo, libsveltosv1alpha1.ClusterInfo{
				Cluster: c,
			})
		}
	}

	finalClusterInfo := roleRequest.Status.ClusterInfo
	finalClusterInfo = append(finalClusterInfo, newClusterInfo...)
	roleRequestScope.SetClusterInfo(finalClusterInfo)
}
