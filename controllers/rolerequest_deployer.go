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
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	"github.com/gdexlab/go-render/render"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/util/annotations"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectsveltos/access-manager/pkg/scope"
	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
	"github.com/projectsveltos/libsveltos/lib/clusterproxy"
	"github.com/projectsveltos/libsveltos/lib/deployer"
	"github.com/projectsveltos/libsveltos/lib/k8s_utils"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
	"github.com/projectsveltos/libsveltos/lib/pullmode"
	"github.com/projectsveltos/libsveltos/lib/roles"
)

type getCurrentHash func(ctx context.Context, c client.Client, cluster *corev1.ObjectReference,
	roleRequest *libsveltosv1beta1.RoleRequest, logger logr.Logger) ([]byte, error)

type feature struct {
	id          string
	currentHash getCurrentHash
	deploy      deployer.RequestHandler
	undeploy    deployer.RequestHandler
}

func (r *RoleRequestReconciler) deployRoleRequest(ctx context.Context, roleRequestScope *scope.RoleRequestScope,
	f feature, logger logr.Logger) error {

	roleRequest := roleRequestScope.RoleRequest

	logger = logger.WithValues("rolerequest", roleRequest.Name)
	logger.V(logs.LogDebug).Info("request to deploy")

	var errorSeen error
	allDeployed := true
	clusterInfo := make([]libsveltosv1beta1.ClusterInfo, 0)
	for i := range roleRequest.Status.ClusterInfo {
		c := roleRequest.Status.ClusterInfo[i]
		cInfo, err := r.processRoleRequest(ctx, roleRequestScope, &c.Cluster, f, logger)
		if err != nil {
			errorSeen = err
		}
		if cInfo != nil {
			clusterInfo = append(clusterInfo, *cInfo)
			if cInfo.Status != libsveltosv1beta1.SveltosStatusProvisioned {
				allDeployed = false
			}
		}
	}

	// Update Classifier Status
	roleRequestScope.SetClusterInfo(clusterInfo)

	if errorSeen != nil {
		return errorSeen
	}

	if !allDeployed {
		return fmt.Errorf("request to deploy RoleRequest is still queued in one ore more clusters")
	}

	return nil
}

func (r *RoleRequestReconciler) undeployRoleRequest(ctx context.Context, roleRequestScope *scope.RoleRequestScope,
	f feature, logger logr.Logger) error {

	roleRequest := roleRequestScope.RoleRequest

	logger.V(logs.LogDebug).Info("request to undeploy")

	clusters := make([]*corev1.ObjectReference, 0)
	// Get list of clusters where RoleRequest needs to be removed
	for i := range roleRequest.Status.ClusterInfo {
		c := &roleRequest.Status.ClusterInfo[i].Cluster
		_, err := clusterproxy.GetCluster(ctx, r.Client, c.Namespace, c.Name, clusterproxy.GetClusterType(c))
		if err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(logs.LogInfo).Info(fmt.Sprintf("cluster %s/%s does not exist", c.Namespace, c.Name))
				continue
			}
			logger.V(logs.LogInfo).Info("failed to get cluster")
			return err
		}
		clusters = append(clusters, c)
	}

	clusterInfo := make([]libsveltosv1beta1.ClusterInfo, 0)
	for i := range clusters {
		c := clusters[i]
		err := r.removeRoleRequest(ctx, roleRequestScope, c, f, logger)
		if err != nil {
			failureMessage := err.Error()
			clusterInfo = append(clusterInfo, libsveltosv1beta1.ClusterInfo{
				Cluster:        *c,
				Status:         libsveltosv1beta1.SveltosStatusRemoving,
				FailureMessage: &failureMessage,
			})
		}
	}

	if len(clusterInfo) != 0 {
		matchingClusterRefs := make([]corev1.ObjectReference, len(clusterInfo))
		for i := range clusterInfo {
			matchingClusterRefs[i] = clusterInfo[i].Cluster
		}
		roleRequestScope.SetMatchingClusterRefs(matchingClusterRefs)
		return fmt.Errorf("still in the process of removing RoleRequest from %d clusters",
			len(clusterInfo))
	}

	roleRequestScope.SetClusterInfo(clusterInfo)

	return nil
}

// roleRequestHash returns the RoleRequest hash. It considers RoleRequest Spec and
// all referenced resources
func roleRequestHash(ctx context.Context, c client.Client, cluster *corev1.ObjectReference,
	roleRequest *libsveltosv1beta1.RoleRequest, logger logr.Logger) ([]byte, error) {

	h := sha256.New()
	var config string
	config += render.AsCode(roleRequest.Spec)

	resources, err := collectReferencedObjects(ctx, c, cluster, roleRequest.Spec.RoleRefs, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to collect referenced resources: %v", err))
		return nil, err
	}

	for i := range resources {
		config += render.AsCode(resources[i])
	}

	h.Write([]byte(config))
	return h.Sum(nil), nil
}

// processRoleRequest detect whether it is needed to deploy RoleRequest in current passed cluster.
func (r *RoleRequestReconciler) processRoleRequest(ctx context.Context, roleRequestScope *scope.RoleRequestScope,
	cluster *corev1.ObjectReference, f feature, logger logr.Logger,
) (*libsveltosv1beta1.ClusterInfo, error) {

	roleRequest := roleRequestScope.RoleRequest
	proceed, err := r.canProceed(ctx, roleRequest, cluster, logger)
	if err != nil {
		return nil, err
	} else if !proceed {
		return nil, nil
	}

	// Get RoleRequest Spec hash (at this very precise moment)
	var currentHash []byte
	currentHash, err = roleRequestHash(ctx, r.Client, cluster, roleRequestScope.RoleRequest, logger)
	if err != nil {
		return nil, err
	}

	// If undeploying feature is in progress, wait for it to complete.
	// Otherwise, if we redeploy feature while same feature is still being cleaned up, if two workers process those request in
	// parallel some resources might end up missing.
	if r.Deployer.IsInProgress(cluster.Namespace, cluster.Name, roleRequest.Name, f.id,
		clusterproxy.GetClusterType(cluster), true) {

		logger.V(logs.LogDebug).Info("cleanup is in progress")
		return nil, fmt.Errorf("cleanup of %s in cluster still in progress. Wait before redeploying", f.id)
	}

	// Get the RoleRequest hash when it was last deployed in this cluster (if ever)
	hash, _ := r.getRoleRequestInClusterHashAndStatus(roleRequest, cluster)
	isConfigSame := reflect.DeepEqual(hash, currentHash)
	if !isConfigSame {
		logger.V(logs.LogDebug).Info(fmt.Sprintf("RoleRequest has changed. Current hash %v. Previous hash %v",
			currentHash, hash))
	}

	isPullMode, err := clusterproxy.IsClusterInPullMode(ctx, r.Client, cluster.Namespace,
		cluster.Name, clusterproxy.GetClusterType(cluster), logger)
	if err != nil {
		msg := fmt.Sprintf("failed to verify if Cluster is in pull mode: %v", err)
		logger.V(logs.LogDebug).Info(msg)
		return nil, err
	}

	// Check if TokenRequest is expired. Recreate if so.
	var timeExpired bool
	if !isPullMode {
		// In both push and pull mode, a ServiceAccount (with associated Role/ClusterRole instances) is
		// created in the managed cluster.
		// In push mode a token based Kubeconfig is created for this ServiceAccount and that is stored
		// in the management cluster.
		// In pull mode though there is no direct access to the managed cluster kubeconfig. So this
		// Secret is not created. Rather ConfigurationGroup contains the ServiceAccount information
		// and sveltos-applier impersonate it when applying resources to the managed cluster
		timeExpired, err = isTimeExpired(ctx, r.Client, roleRequest, cluster.Namespace, cluster.Name,
			clusterproxy.GetClusterType(cluster), logger)
		if err != nil {
			return nil, err
		}
	}

	return r.proceedProcessingRoleRequest(ctx, roleRequestScope, cluster, isPullMode, isConfigSame, timeExpired,
		currentHash, f, logger)
}

func (r *RoleRequestReconciler) proceedProcessingRoleRequest(ctx context.Context, roleRequestScope *scope.RoleRequestScope,
	cluster *corev1.ObjectReference, isPullMode, isConfigSame, timeExpired bool, currentHash []byte, f feature,
	logger logr.Logger) (*libsveltosv1beta1.ClusterInfo, error) {

	roleRequest := roleRequestScope.RoleRequest
	_, currentStatus := r.getRoleRequestInClusterHashAndStatus(roleRequest, cluster)

	var deployerStatus *libsveltosv1beta1.SveltosFeatureStatus
	var result deployer.Result

	needToRedeploy := !isConfigSame || timeExpired

	if !needToRedeploy {
		logger.V(logs.LogInfo).Info("roleRequest has not changed and timer has not expired ")
		result = r.Deployer.GetResult(ctx, cluster.Namespace, cluster.Name, roleRequest.Name, f.id,
			clusterproxy.GetClusterType(cluster), false)
		deployerStatus = r.convertResultStatus(result)
	}

	if deployerStatus != nil {
		logger.V(logs.LogDebug).Info("result is available. updating status.")
		var errorMessage string
		if result.Err != nil {
			errorMessage = result.Err.Error()
		}
		clusterInfo := &libsveltosv1beta1.ClusterInfo{
			Cluster:        *cluster,
			Status:         *deployerStatus,
			Hash:           currentHash,
			FailureMessage: &errorMessage,
		}

		if *deployerStatus == libsveltosv1beta1.SveltosStatusProvisioned {
			if isPullMode {
				// provisioned here means configuration for sveltos-applier has been successufully prepared.
				// In pull mode, verify now agent has deployed the configuration.
				return r.proceedDeployingRoleRequestInPullMode(ctx, roleRequestScope, cluster, f, isConfigSame,
					currentHash, logger)
			}
			return clusterInfo, nil
		}
		if *deployerStatus == libsveltosv1beta1.SveltosStatusProvisioning {
			return clusterInfo, fmt.Errorf("roleRequest is still being provisioned")
		}
	} else if !needToRedeploy && currentStatus != nil && *currentStatus == libsveltosv1beta1.SveltosStatusProvisioned {
		logger.V(logs.LogInfo).Info("already deployed")
		s := libsveltosv1beta1.SveltosStatusProvisioned
		deployerStatus = &s
	} else {
		logger.V(logs.LogInfo).Info("no result is available/redeploy is needed. queue job and mark status as provisioning")
		s := libsveltosv1beta1.SveltosStatusProvisioning
		deployerStatus = &s

		// Getting here means either RoleRequest failed to be deployed or RoleRequest has changed.
		// RoleRequest must be (re)deployed.
		if err := r.Deployer.Deploy(ctx, cluster.Namespace, cluster.Name, roleRequest.Name, f.id,
			clusterproxy.GetClusterType(cluster), false, f.deploy, programDuration, deployer.Options{}); err != nil {
			return nil, err
		}
	}

	clusterInfo := &libsveltosv1beta1.ClusterInfo{
		Cluster:        *cluster,
		Status:         *deployerStatus,
		Hash:           currentHash,
		FailureMessage: nil,
	}

	return clusterInfo, nil
}

func (r *RoleRequestReconciler) proceedDeployingRoleRequestInPullMode(ctx context.Context,
	roleRequestScope *scope.RoleRequestScope, cluster *corev1.ObjectReference, f feature,
	isConfigSame bool, currentHash []byte, logger logr.Logger) (*libsveltosv1beta1.ClusterInfo, error) {

	var pullmodeStatus *libsveltosv1beta1.FeatureStatus

	roleRequest := roleRequestScope.RoleRequest
	if isConfigSame {
		pullmodeHash, err := pullmode.GetRequestorHash(ctx, getManagementClusterClient(),
			cluster.Namespace, cluster.Name, libsveltosv1beta1.RoleRequestKind, roleRequest.Name, f.id, logger)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				msg := fmt.Sprintf("failed to get pull mode hash: %v", err)
				logger.V(logs.LogDebug).Info(msg)
				return nil, err
			}
		} else {
			isConfigSame = reflect.DeepEqual(pullmodeHash, currentHash)
		}
	}

	if isConfigSame {
		// only if configuration hash matches, check if feature is deployed
		logger.V(logs.LogDebug).Info("hash has not changed")
		var err error
		pullmodeStatus, err = r.proceesAgentDeploymentStatus(ctx, roleRequest, cluster, f, logger)
		if err != nil {
			return nil, err
		}
	}

	clusterInfo := &libsveltosv1beta1.ClusterInfo{
		Cluster:        *cluster,
		Hash:           currentHash,
		FailureMessage: nil,
	}

	if pullmodeStatus != nil {
		logger.V(logs.LogDebug).Info(fmt.Sprintf("agent result is available. updating status: %v", *pullmodeStatus))
		switch *pullmodeStatus {
		case libsveltosv1beta1.FeatureStatusProvisioned:
			if err := pullmode.TerminateDeploymentTracking(ctx, r.Client, cluster.Namespace,
				cluster.Name, libsveltosv1beta1.RoleRequestKind, roleRequest.Name, f.id, logger); err != nil {
				logger.V(logs.LogDebug).Info(fmt.Sprintf("failed to terminate tracking: %v", err))
				return nil, err
			}
			provisioned := libsveltosv1beta1.SveltosStatusProvisioned
			clusterInfo.Status = provisioned
			return clusterInfo, nil
		case libsveltosv1beta1.FeatureStatusProvisioning:
			msg := "agent is provisioning the content"
			logger.V(logs.LogDebug).Info(msg)
			provisioning := libsveltosv1beta1.SveltosStatusProvisioning
			clusterInfo.Status = provisioning
			return clusterInfo, nil
		case libsveltosv1beta1.FeatureStatusFailed:
			logger.V(logs.LogDebug).Info("agent failed provisioning the content")
			failed := libsveltosv1beta1.SveltosStatusFailed
			clusterInfo.Status = failed
		case libsveltosv1beta1.FeatureStatusFailedNonRetriable, libsveltosv1beta1.FeatureStatusRemoving,
			libsveltosv1beta1.FeatureStatusAgentRemoving, libsveltosv1beta1.FeatureStatusRemoved:
			logger.V(logs.LogDebug).Info("proceed deploying")
		}
	} else {
		provisioning := libsveltosv1beta1.SveltosStatusProvisioning
		clusterInfo.Status = provisioning
	}

	// Getting here means either agent failed to deploy feature or configuration has changed.
	// Either way, feature must be (re)deployed. Queue so new configuration for agent is prepared.
	options := deployer.Options{HandlerOptions: make(map[string]any)}
	options.HandlerOptions[configurationHash] = currentHash

	logger.V(logs.LogDebug).Info("queueing request to deploy")
	if err := r.Deployer.Deploy(ctx, cluster.Namespace, cluster.Name,
		roleRequest.Name, f.id, clusterproxy.GetClusterType(cluster), false,
		f.deploy, programDuration, options); err != nil {
		return nil, err
	}

	return clusterInfo, fmt.Errorf("request to deploy queued")
}

// If SveltosCluster is in pull mode, verify whether agent has pulled and successuffly deployed it.
func (r *RoleRequestReconciler) proceesAgentDeploymentStatus(ctx context.Context,
	roleRequest *libsveltosv1beta1.RoleRequest, cluster *corev1.ObjectReference, f feature, logger logr.Logger,
) (*libsveltosv1beta1.FeatureStatus, error) {

	logger.V(logs.LogDebug).Info("Verify if agent has deployed content and process it")

	status, err := pullmode.GetDeploymentStatus(ctx, r.Client, cluster.Namespace, cluster.Name,
		libsveltosv1beta1.RoleRequestKind, roleRequest.Name, f.id, logger)

	if err != nil {
		if pullmode.IsProcessingMismatch(err) {
			provisioning := libsveltosv1beta1.FeatureStatusProvisioning
			return &provisioning, nil
		}
		return nil, err
	}

	return status.DeploymentStatus, err
}

// removeRoleRequest removes RoleRequest resources from cluster
func (r *RoleRequestReconciler) removeRoleRequest(ctx context.Context, roleRequestScope *scope.RoleRequestScope,
	cluster *corev1.ObjectReference, f feature, logger logr.Logger,
) error {

	roleRequest := roleRequestScope.RoleRequest

	paused, err := r.isPaused(ctx, cluster, roleRequest)
	if err != nil {
		return err
	}
	if paused {
		logger.V(logs.LogInfo).Info("cluster is paused. Do nothing.")
		return nil
	}

	// If deploying feature is in progress, wait for it to complete.
	// Otherwise, if we undeploy feature while same feature is still being deployed, if two workers process those request in
	// parallel some resources might end stale.
	if r.Deployer.IsInProgress(cluster.Namespace, cluster.Name, roleRequest.Name, f.id,
		clusterproxy.GetClusterType(cluster), false) {

		logger.V(logs.LogDebug).Info("deploy is in progress")
		return fmt.Errorf("deploy of %s in cluster still in progress. Wait before redeploying", f.id)
	}

	result := r.Deployer.GetResult(ctx, cluster.Namespace, cluster.Name, roleRequest.Name, f.id,
		clusterproxy.GetClusterType(cluster), true)
	status := r.convertResultStatus(result)

	if status != nil {
		if *status == libsveltosv1beta1.SveltosStatusProvisioning {
			return fmt.Errorf("feature is still being removed")
		}
		if *status == libsveltosv1beta1.SveltosStatusRemoved {
			return nil
		}
	} else {
		logger.V(logs.LogDebug).Info("no result is available")
	}

	logger.V(logs.LogDebug).Info("queueing request to un-deploy")
	if err := r.Deployer.Deploy(ctx, cluster.Namespace, cluster.Name, roleRequest.Name, f.id,
		clusterproxy.GetClusterType(cluster), true, f.undeploy, programDuration, deployer.Options{}); err != nil {
		return err
	}

	return fmt.Errorf("cleanup request is queued")
}

// canProceed returns true if cluster is ready to be programmed and it is not paused.
func (r *RoleRequestReconciler) canProceed(ctx context.Context, roleRequest *libsveltosv1beta1.RoleRequest,
	cluster *corev1.ObjectReference, logger logr.Logger) (bool, error) {

	logger = logger.WithValues("clusterNamespace", cluster.Namespace, "clusterName", cluster.Name)

	paused, err := r.isPaused(ctx, cluster, roleRequest)
	if err != nil {
		return false, err
	}

	if paused {
		logger.V(logs.LogDebug).Info("Cluster is paused")
		return false, nil
	}

	ready, err := clusterproxy.IsClusterReadyToBeConfigured(ctx, r.Client, cluster, logger)
	if err != nil {
		return false, err
	}

	if !ready {
		logger.V(logs.LogInfo).Info("Cluster is not ready yet")
		return false, nil
	}

	return true, nil
}

// isPaused returns true if Sveltos/CAPI Cluster is paused or ClusterSummary has paused annotation.
func (r *RoleRequestReconciler) isPaused(ctx context.Context, cluster *corev1.ObjectReference,
	roleRequest *libsveltosv1beta1.RoleRequest) (bool, error) {

	isClusterPaused, err := clusterproxy.IsClusterPaused(ctx, r.Client, cluster.Namespace, cluster.Name,
		clusterproxy.GetClusterType(cluster))

	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	if isClusterPaused {
		return true, nil
	}

	return annotations.HasPaused(roleRequest), nil
}

// getRoleRequestInClusterHashAndStatus returns the hash of the RoleRequest that was deployed in a given
// Cluster (if ever deployed)
func (r *RoleRequestReconciler) getRoleRequestInClusterHashAndStatus(roleRequest *libsveltosv1beta1.RoleRequest,
	cluster *corev1.ObjectReference) ([]byte, *libsveltosv1beta1.SveltosFeatureStatus) {

	for i := range roleRequest.Status.ClusterInfo {
		cInfo := &roleRequest.Status.ClusterInfo[i]
		if cInfo.Cluster.Namespace == cluster.Namespace &&
			cInfo.Cluster.Name == cluster.Name &&
			cInfo.Cluster.APIVersion == cluster.APIVersion &&
			cInfo.Cluster.Kind == cluster.Kind {

			return cInfo.Hash, &cInfo.Status
		}
	}

	return nil, nil
}

func (r *RoleRequestReconciler) convertResultStatus(result deployer.Result) *libsveltosv1beta1.SveltosFeatureStatus {
	switch result.ResultStatus {
	case deployer.Deployed:
		s := libsveltosv1beta1.SveltosStatusProvisioned
		return &s
	case deployer.Failed:
		s := libsveltosv1beta1.SveltosStatusFailed
		return &s
	case deployer.InProgress:
		s := libsveltosv1beta1.SveltosStatusProvisioning
		return &s
	case deployer.Removed:
		s := libsveltosv1beta1.SveltosStatusRemoved
		return &s
	case deployer.Unavailable:
		return nil
	}

	return nil
}

func deployRoleRequestInCluster(ctx context.Context, c client.Client,
	clusterNamespace, clusterName, applicant, featureID string,
	clusterType libsveltosv1beta1.ClusterType, options deployer.Options, logger logr.Logger,
) error {

	// In the managed cluster following resources will be created:
	// - Create a ServiceAccount
	// - For each referenced resource (ConfigMap/Secret) get content and deploy all ClusterRole/Role
	// - For each deployed ClusterRole/Role create corresponding ClusterRoleBinding/RoleBinding associating
	// ClusterRole/Role with ServiceAccount created above

	// In the management cluster following resource will be created:
	// - Secret containing the kubeconfig associated to ServiceAccount created in the managed cluster

	logger = logger.WithValues("roleRequest", applicant)
	logger = logger.WithValues("cluster", fmt.Sprintf("%s/%s", clusterNamespace, clusterName))

	roleRequest := &libsveltosv1beta1.RoleRequest{}
	err := c.Get(ctx, types.NamespacedName{Name: applicant}, roleRequest)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get roleRequest: %v", err))
		return err
	}

	if !roleRequest.DeletionTimestamp.IsZero() {
		logger.V(logs.LogDebug).Info("roleRequest marked for deletion")
		return nil
	}

	isPullMode, err := clusterproxy.IsClusterInPullMode(ctx, c, clusterNamespace, clusterName, clusterType, logger)
	if err != nil {
		return err
	}

	if isPullMode {
		return proceedDeployingRoleRequestInPullMode(ctx, c, roleRequest, clusterNamespace, clusterName,
			clusterType, options, logger)
	}

	logger.V(logs.LogDebug).Info("Deploy roleRequest")
	return proceedDeployingRoleRequestInCluster(ctx, c, roleRequest, clusterNamespace, clusterName,
		clusterType, logger)
}

func proceedDeployingRoleRequestInPullMode(ctx context.Context, c client.Client,
	roleRequest *libsveltosv1beta1.RoleRequest, clusterNamespace, clusterName string,
	clusterType libsveltosv1beta1.ClusterType, options deployer.Options, logger logr.Logger,
) error {

	logger.V(logs.LogDebug).Info("Deploy roleRequest in pullmode")

	// Create ServiceAccount and all referenced (Cluster)Role/(ClusterRole)Binding to the managed cluster
	toDeployServiceAccount := getServiceAccountToDeploy(roleRequest)
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&toDeployServiceAccount)
	if err != nil {
		logger.V(logs.LogDebug).Info(fmt.Sprintf("failed to convert RoleRequest instance to unstructured: %v", err))
	}

	u := &unstructured.Unstructured{}
	u.SetUnstructuredContent(unstructuredObj)

	objects := []unstructured.Unstructured{*u}

	clusterRef := &corev1.ObjectReference{Namespace: clusterNamespace, Name: clusterName}
	if clusterType == libsveltosv1beta1.ClusterTypeSveltos {
		clusterRef.Kind = libsveltosv1beta1.SveltosClusterKind
		clusterRef.APIVersion = libsveltosv1beta1.GroupVersion.String()
	} else {
		clusterRef.Kind = clusterv1.ClusterKind
		clusterRef.APIVersion = clusterv1.GroupVersion.String()
	}

	// Collect all RoleRequest's referenced ConfigMap/Secret. The content stored in those referenced
	// resources is a set of Role/ClusterRole instances that need to be deployed.
	var refObjects []client.Object
	refObjects, err = collectReferencedObjects(ctx, c, clusterRef, roleRequest.Spec.RoleRefs, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to collect referenced resources: %v", err))
		return err
	}

	for i := range refObjects {
		// For reach referenced resource (either a ConfigMap or Secret), collect the content stored in data
		// section
		referencedObjects, err := collectContentFromReferencedResource(refObjects[i], roleRequest, logger)
		if err != nil {
			logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to collect content from referenced resource: %v", err))
			return err
		}

		objects = append(objects, referencedObjects...)
	}

	resources := map[string][]unstructured.Unstructured{}
	resources["rolerequest"] = objects

	configurationHash, _ := options.HandlerOptions[configurationHash].([]byte)
	setters := prepareSetters(roleRequest, configurationHash)
	return pullmode.RecordResourcesForDeployment(ctx, c, clusterNamespace, clusterName,
		libsveltosv1beta1.RoleRequestKind, roleRequest.Name, libsveltosv1beta1.FeatureRoleRequest,
		resources, logger, setters...)
}

func collectContentFromReferencedResource(resource client.Object, roleRequest *libsveltosv1beta1.RoleRequest,
	logger logr.Logger) ([]unstructured.Unstructured, error) {

	var collectedResources []*unstructured.Unstructured
	var err error

	switch resource.GetObjectKind().GroupVersionKind().Kind {
	case configMapKind:
		configMap := resource.(*corev1.ConfigMap)
		l := logger.WithValues("configMapNamespace", configMap.Namespace, "configMapName", configMap.Name)
		l.V(logs.LogDebug).Info("collect ConfigMap content")
		collectedResources, err = collectContent(configMap.Data, logger)
	case secretKind:
		secret := resource.(*corev1.Secret)
		l := logger.WithValues("secretNamespace", secret.Namespace, "secretName", secret.Name)
		l.V(logs.LogDebug).Info("collect Secret content")
		data := make(map[string]string)
		for key, value := range secret.Data {
			data[key] = string(value)
		}
		collectedResources, err = collectContent(data, logger)
	default:
		return nil, fmt.Errorf("referenced GVK %s not supported", resource.GetObjectKind().GroupVersionKind())
	}

	if err != nil {
		return nil, err
	}

	var unstructuredObj map[string]interface{}
	const factor = 2 // for every Role a RoleBinding will be added. For every ClusterRole a ClusterRoleBinding will be added
	result := make([]unstructured.Unstructured, 0, factor*len(collectedResources))
	for i := range collectedResources {
		if !isClusterRoleOrRole(collectedResources[i], logger) {
			logger.V(logs.LogInfo).Info("Resource %s %s:%s is not ClusterRole/Role",
				collectedResources[i].GetKind(), collectedResources[i].GetNamespace(), collectedResources[i].GetName())
			continue
		}
		addTypeInformationToObject(getManagementClusterScheme(), collectedResources[i])
		result = append(result, *collectedResources[i])

		if collectedResources[i].GetKind() == roleKind {
			roleBinding := getRoleBinding(collectedResources[i], roleRequest)
			addTypeInformationToObject(getManagementClusterScheme(), roleBinding)
			unstructuredObj, err = runtime.DefaultUnstructuredConverter.ToUnstructured(&roleBinding)
		} else {
			clusterRoleBinding := getClusterRoleBinding(collectedResources[i], roleRequest)
			addTypeInformationToObject(getManagementClusterScheme(), clusterRoleBinding)
			unstructuredObj, err = runtime.DefaultUnstructuredConverter.ToUnstructured(&clusterRoleBinding)
		}

		if err != nil {
			return nil, err
		}

		u := &unstructured.Unstructured{}
		u.SetUnstructuredContent(unstructuredObj)
		result = append(result, *u)
	}

	return result, nil
}

func proceedDeployingRoleRequestInCluster(ctx context.Context, c client.Client,
	roleRequest *libsveltosv1beta1.RoleRequest, clusterNamespace, clusterName string,
	clusterType libsveltosv1beta1.ClusterType, logger logr.Logger,
) error {

	remoteClient, err := clusterproxy.GetKubernetesClient(ctx, c, clusterNamespace, clusterName, "", "",
		clusterType, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get remote client: %v", err))
		return err
	}

	var remoteRestConfig *rest.Config
	remoteRestConfig, err = clusterproxy.GetKubernetesRestConfig(ctx, c, clusterNamespace, clusterName, "", "",
		clusterType, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get remote restConfig: %v", err))
		return err
	}

	err = createServiceAccountInManagedCluster(ctx, remoteClient, roleRequest)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to create ServiceAccount: %v", err))
		return err
	}

	// Take Kubeconfig associated to ServiceAccount in the managed cluster, and store it in a Secret in the
	// management cluster. This Kubeconfig will later be used when deploying add-ons for a ClusterProfile created
	// by a tenant admin
	err = createServiceAccountSecretForCluster(ctx, remoteRestConfig, c,
		clusterNamespace, clusterName, roleRequest.Spec.ServiceAccountNamespace, roleRequest.Spec.ServiceAccountName,
		clusterType, roleRequest, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to create Secret with kubeconfig for ServiceAccount: %v", err))
		return err
	}

	clusterRef := &corev1.ObjectReference{Namespace: clusterNamespace, Name: clusterName}
	if clusterType == libsveltosv1beta1.ClusterTypeSveltos {
		clusterRef.Kind = libsveltosv1beta1.SveltosClusterKind
		clusterRef.APIVersion = libsveltosv1beta1.GroupVersion.String()
	} else {
		clusterRef.Kind = clusterv1.ClusterKind
		clusterRef.APIVersion = clusterv1.GroupVersion.String()
	}

	var resources []client.Object
	resources, err = collectReferencedObjects(ctx, c, clusterRef, roleRequest.Spec.RoleRefs, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to collect referenced resources: %v", err))
		return err
	}

	deployedResources := make([]corev1.ObjectReference, 0)
	for i := range resources {
		referencedResource := resources[i]
		var tmpDeployedResources []corev1.ObjectReference
		tmpDeployedResources, err = deployReferencedResourceInManagedCluster(ctx, remoteRestConfig, remoteClient,
			referencedResource, roleRequest, logger)
		if err != nil {
			logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to deploy referenced resource %s %s/%s: %v",
				referencedResource.GetObjectKind(), referencedResource.GetNamespace(), referencedResource.GetName(), err))
			return err
		}
		deployedResources = append(deployedResources, tmpDeployedResources...)
	}

	// Clean stale resources
	return cleanStaleResources(ctx, remoteClient, roleRequest, deployedResources, logger)
}

func removeServiceAccount(ctx context.Context, remoteClient client.Client, roleRequest *libsveltosv1beta1.RoleRequest,
	logger logr.Logger) error {

	// Generate the name of the corresponding ServiceAccount in the managed cluster
	saName := roles.GetServiceAccountNameInManagedCluster(roleRequest.Spec.ServiceAccountNamespace, roleRequest.Spec.ServiceAccountName)
	serviceAccount := &corev1.ServiceAccount{}
	err := remoteClient.Get(ctx, client.ObjectKey{Namespace: serviceAccountNamespace, Name: saName},
		serviceAccount)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(logs.LogDebug).Info("serviceaccount not found")
			return nil
		}
	}

	if k8s_utils.IsOnlyOwnerReference(serviceAccount, roleRequest) {
		return remoteClient.Delete(ctx, serviceAccount)
	}

	k8s_utils.RemoveOwnerReference(serviceAccount, roleRequest)
	return remoteClient.Update(ctx, serviceAccount)
}

func cleanStaleResources(ctx context.Context, remoteClient client.Client, roleRequest *libsveltosv1beta1.RoleRequest,
	deployedResources []corev1.ObjectReference, logger logr.Logger) error {

	// Create a map of resources just deployed
	currentPolicies := make(map[string]bool, 0)
	for i := range deployedResources {
		key := getPolicyInfo(&deployedResources[i])
		currentPolicies[key] = true
	}

	if err := cleanStaleClusterRoleResources(ctx, remoteClient, roleRequest, currentPolicies, logger); err != nil {
		return err
	}

	if err := cleanStaleRoleResources(ctx, remoteClient, roleRequest, currentPolicies, logger); err != nil {
		return err
	}

	return nil
}

func removeRoleRequestSecrets(ctx context.Context, c client.Client, roleRequest *libsveltosv1beta1.RoleRequest,
	clusterNamespace, clusterName string, clusterType libsveltosv1beta1.ClusterType, logger logr.Logger) error {

	logger = logger.WithValues("roleRequest", roleRequest.Name)
	logger = logger.WithValues("cluster", fmt.Sprintf("%s/%s", clusterNamespace, clusterName))
	logger = logger.WithValues("serviceaccount", fmt.Sprintf("%s/%s",
		roleRequest.Spec.ServiceAccountNamespace, roleRequest.Spec.ServiceAccountName))

	logger.V(logs.LogDebug).Info("Removing secret")

	return roles.DeleteSecret(ctx, c, clusterNamespace, clusterName, roleRequest.Spec.ServiceAccountNamespace,
		roleRequest.Spec.ServiceAccountName, clusterType, roleRequest)
}

func cleanStaleClusterRoleResources(ctx context.Context, remoteClient client.Client, roleRequest *libsveltosv1beta1.RoleRequest,
	currentPolicies map[string]bool, logger logr.Logger) error {

	// fetch all ClusterRoles
	clusterRoleList := &rbacv1.ClusterRoleList{}
	err := remoteClient.List(ctx, clusterRoleList)
	if err != nil {
		return err
	}

	for i := range clusterRoleList.Items {
		cr := &clusterRoleList.Items[i]
		logger.V(logs.LogVerbose).Info("considering clusterRole %s", cr.GetName())
		// Verify if this policy was deployed because of a clustersummary (ReferenceLabelName
		// is present as label in such a case).
		if !hasAnnotation(cr, deployer.ReferenceNameAnnotation, "") {
			continue
		}

		clusterRoleRef := &corev1.ObjectReference{
			Kind: clusterRoleKind,
			Name: cr.Name,
		}

		if _, ok := currentPolicies[getPolicyInfo(clusterRoleRef)]; !ok {
			var content map[string]interface{}
			content, err = runtime.DefaultUnstructuredConverter.ToUnstructured(cr)
			if err != nil {
				return err
			}

			var u unstructured.Unstructured
			u.SetUnstructuredContent(content)

			if k8s_utils.IsOnlyOwnerReference(&u, roleRequest) {
				// First remove ClusterRoleBinding, then ClusterRole cause we find ClusterRoleBinding
				// only after detecting a ClusterRole needs to be deleted
				err = deleteClusterRoleBinding(ctx, remoteClient, cr.Name)
				if err != nil {
					return err
				}

				err = remoteClient.Delete(ctx, cr)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func cleanStaleRoleResources(ctx context.Context, remoteClient client.Client, roleRequest *libsveltosv1beta1.RoleRequest,
	currentPolicies map[string]bool, logger logr.Logger) error {

	// fetch all ClusterRoles
	roleList := &rbacv1.RoleList{}
	err := remoteClient.List(ctx, roleList)
	if err != nil {
		return err
	}

	for i := range roleList.Items {
		r := &roleList.Items[i]
		logger.V(logs.LogVerbose).Info("considering role %s:%s", r.GetNamespace(), r.GetName())
		// Verify if this policy was deployed because of a clustersummary (ReferenceLabelName
		// is present as label in such a case).
		if !hasAnnotation(r, deployer.ReferenceNameAnnotation, "") {
			continue
		}

		roleRef := &corev1.ObjectReference{
			Kind:      roleKind,
			Name:      r.Name,
			Namespace: r.Namespace,
		}

		if _, ok := currentPolicies[getPolicyInfo(roleRef)]; !ok {
			var content map[string]interface{}
			content, err = runtime.DefaultUnstructuredConverter.ToUnstructured(r)
			if err != nil {
				return err
			}

			var u unstructured.Unstructured
			u.SetUnstructuredContent(content)

			if k8s_utils.IsOnlyOwnerReference(&u, roleRequest) {
				// First remove RoleBinding, then Role cause we find RoleBinding
				// only after detecting a Role needs to be deleted
				err = deleteRoleBinding(ctx, remoteClient, r.Namespace, r.Name)
				if err != nil {
					return err
				}

				err = remoteClient.Delete(ctx, r)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func deleteClusterRoleBinding(ctx context.Context, remoteClient client.Client, name string) error {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	err := remoteClient.Get(ctx, types.NamespacedName{Name: name}, clusterRoleBinding)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return remoteClient.Delete(ctx, clusterRoleBinding)
}

func deleteRoleBinding(ctx context.Context, remoteClient client.Client, namespace, name string) error {
	roleBinding := &rbacv1.RoleBinding{}
	err := remoteClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, roleBinding)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return remoteClient.Delete(ctx, roleBinding)
}

// undeployRoleRequestFromCluster deletes RoleRequest resources from cluster
func undeployRoleRequestFromCluster(ctx context.Context, c client.Client,
	clusterNamespace, clusterName, applicant, featureID string,
	clusterType libsveltosv1beta1.ClusterType, options deployer.Options, logger logr.Logger) error {

	logger = logger.WithValues("roleRequest", applicant)
	logger = logger.WithValues("cluster", fmt.Sprintf("%s/%s", clusterNamespace, clusterName))

	roleRequest := &libsveltosv1beta1.RoleRequest{}
	err := c.Get(ctx, types.NamespacedName{Name: applicant}, roleRequest)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get roleRequest: %v", err))
		return err
	}

	// If the cluster does not exist anymore, return (cluster has been deleted
	// there is nothing to clear on the managed cluster)
	_, err = clusterproxy.GetCluster(ctx, c, clusterNamespace, clusterName, clusterType)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Remove stale resources on the management cluster
			err = removeRoleRequestSecrets(ctx, c, roleRequest, clusterNamespace, clusterName, clusterType, logger)
			if err != nil {
				return nil
			}
		}
		return err
	}

	isPullMode, err := clusterproxy.IsClusterInPullMode(ctx, c, clusterNamespace, clusterName,
		clusterType, logger)
	if err != nil {
		msg := fmt.Sprintf("failed to verify if Cluster is in pull mode: %v", err)
		logger.V(logs.LogDebug).Info(msg)
		return err
	}

	if isPullMode {
		return undeployRoleRequestInPullMode(ctx, c, clusterNamespace, clusterName, roleRequest, logger)
	}

	remoteClient, err := clusterproxy.GetKubernetesClient(ctx, c, clusterNamespace, clusterName, "", "",
		clusterType, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get remote client: %v", err))
		return err
	}

	// remove serviceaccount
	err = removeServiceAccount(ctx, remoteClient, roleRequest, logger)
	if err != nil {
		return err
	}

	// Clean stale resources
	err = cleanStaleResources(ctx, remoteClient, roleRequest, nil, logger)
	if err != nil {
		return err
	}

	return removeRoleRequestSecrets(ctx, c, roleRequest, clusterNamespace, clusterName, clusterType, logger)
}

func undeployRoleRequestInPullMode(ctx context.Context, c client.Client, clusterNamespace, clusterName string,
	roleRequest *libsveltosv1beta1.RoleRequest, logger logr.Logger) error {

	// RoleRequest follows a strict state machine for resource removal:
	//
	// 1. Create ConfigurationGroup with action=Remove
	// 2. Monitor ConfigurationGroup status:
	//    - Missing ConfigurationGroup = resources successfully removed
	//    - ConfigurationGroup.Status = Removed = resources successfully removed
	var retError error
	agentStatus, err := pullmode.GetRemoveStatus(ctx, c, clusterNamespace, clusterName,
		libsveltosv1beta1.RoleRequestKind, roleRequest.Name, libsveltosv1beta1.RoleRequestKind, logger)
	if err != nil {
		retError = err
	} else if agentStatus != nil {
		if agentStatus.DeploymentStatus != nil && *agentStatus.DeploymentStatus == libsveltosv1beta1.FeatureStatusRemoved {
			logger.V(logs.LogDebug).Info("agent removed content")
			err = pullmode.TerminateDeploymentTracking(ctx, c, clusterNamespace, clusterName,
				libsveltosv1beta1.RoleRequestKind, roleRequest.Name, libsveltosv1beta1.RoleRequestKind, logger)
			if err != nil {
				return err
			}
			return nil
		} else if agentStatus.FailureMessage != nil {
			retError = errors.New(*agentStatus.FailureMessage)
		} else {
			return errors.New("agent is removing classifier instance")
		}
	}

	logger.V(logs.LogDebug).Info("queueing request to un-deploy")
	setters := prepareSetters(roleRequest, nil)
	err = pullmode.RemoveDeployedResources(ctx, c, clusterNamespace, clusterName, libsveltosv1beta1.RoleRequestKind, roleRequest.Name,
		libsveltosv1beta1.RoleRequestKind, logger, setters...)
	if err != nil {
		logger.V(logs.LogDebug).Info(fmt.Sprintf("removeDeployedResources failed: %v", err))
		return err
	}

	if retError != nil {
		return retError
	}

	return fmt.Errorf("agent cleanup request is queued")
}

func getPolicyInfo(policy *corev1.ObjectReference) string {
	return fmt.Sprintf("%s:%s:%s",
		policy.Kind,
		policy.Namespace,
		policy.Name)
}

// hasAnnotation search if key is one of the annotations.
// If value is empty, returns true if key is present.
// If value is not empty, returns true if key is present and value is a match.
func hasAnnotation(u client.Object, key, value string) bool {
	annts := u.GetAnnotations()
	if annts == nil {
		return false
	}

	v, ok := annts[key]

	if value == "" {
		return ok
	}

	return v == value
}

func prepareSetters(roleRequest *libsveltosv1beta1.RoleRequest, configurationHash []byte) []pullmode.Option {
	setters := make([]pullmode.Option, 0)
	setters = append(setters, pullmode.WithRequestorHash(configurationHash))
	sourceRef := corev1.ObjectReference{
		APIVersion: roleRequest.APIVersion,
		Kind:       roleRequest.Kind,
		Name:       roleRequest.Name,
		UID:        roleRequest.UID,
	}

	setters = append(setters, pullmode.WithSourceRef(&sourceRef))

	return setters
}
