/*
Copyright 2022. projectsveltos.io. All rights reserved.

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
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/projectsveltos/access-manager/pkg/scope"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
	libsveltosutils "github.com/projectsveltos/libsveltos/lib/utils"
)

const (
	// expirationInSecond is the token expiration time.
	expirationInSecond = 10 * time.Minute // minimum duration is 10 minutes
)

// AccessRequestReconciler reconciles a AccessRequest obje©∫ct
type AccessRequestReconciler struct {
	client.Client
	*rest.Config
	Scheme               *runtime.Scheme
	ConcurrentReconciles int
}

// ClassifierReports permissions are needed in order to create Role giving classifier-agent permission to
// update ClassifierReport instances.
// ServiceAccount/Role/RoleBinding permissions are needed because while processing AccessRequest, this
// controller creates ServiceAccount/Role/RoleBinding
// Secret permissions are needed because AccessRequestReconciler creates a Secret containing the kubeconfig
// associated to the ServiceAccount it also creates.
// ConfigMap permissions are needed to fetch ca.crt

//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=accessrequests,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=accessrequests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=accessrequests/finalizers,verbs=update
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=classifierreports,verbs=create;list;get;update;watch
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=eventreports,verbs=create;list;get;update;watch
//+kubebuilder:rbac:groups=lib.projectsveltos.io,resources=healthcheckreports,verbs=create;list;get;update;watch
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=create;list;get;delete;update;watch
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create;list;get;delete;update;watch
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=create;get;delete;update;list;watch
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=create;get;delete;update;list;watch

func (r *AccessRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := ctrl.LoggerFrom(ctx)
	logger.V(logs.LogInfo).Info("Reconciling")

	// Fecth the AccessRequest instance
	accessRequest := &libsveltosv1alpha1.AccessRequest{}
	if err := r.Get(ctx, req.NamespacedName, accessRequest); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		logger.Error(err, "Failed to fetch AccessRequest")
		return reconcile.Result{}, errors.Wrapf(
			err,
			"Failed to fetch AccessRequest %s",
			req.NamespacedName,
		)
	}

	logger = logger.WithValues("accessrequest", accessRequest.Name)

	accessRequestScope, err := scope.NewAccessRequestScope(scope.AccessRequestScopeParams{
		Client:         r.Client,
		Logger:         logger,
		AccessRequest:  accessRequest,
		ControllerName: "accessRequest",
	})
	if err != nil {
		logger.Error(err, "Failed to create accessRequestScope")
		return reconcile.Result{}, errors.Wrapf(
			err,
			"unable to create accessRequest scope for %s",
			req.NamespacedName,
		)
	}

	// Always close the scope when exiting this function so we can persist any Classifier
	// changes.
	defer func() {
		if err := accessRequestScope.Close(ctx); err != nil {
			logger.Error(err, "Failed to patch AccessRequest")
			reterr = err
		}
	}()

	// Handle deleted classifier
	if !accessRequest.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, accessRequestScope)
	}

	// Handle non-deleted accessRequestScope
	return r.reconcileNormal(ctx, accessRequestScope)
}

func (r *AccessRequestReconciler) reconcileDelete(
	ctx context.Context,
	accessRequestScope *scope.AccessRequestScope,
) (reconcile.Result, error) {

	logger := accessRequestScope.Logger
	logger.V(logs.LogInfo).Info("Reconciling AccessRequest delete")

	err := r.cleanup(ctx, accessRequestScope, logger)
	if err != nil {
		failureMessage := err.Error()
		accessRequestScope.SetFailureMessage(&failureMessage)
		return reconcile.Result{}, err
	}

	// Cluster is deleted so remove the finalizer.
	logger.Info("Removing finalizer")
	controllerutil.RemoveFinalizer(accessRequestScope.AccessRequest, libsveltosv1alpha1.AccessRequestFinalizer)

	logger.V(logs.LogInfo).Info("Reconcile delete success")
	return reconcile.Result{}, nil
}

func (r *AccessRequestReconciler) reconcileNormal(
	ctx context.Context,
	accessRequestScope *scope.AccessRequestScope,
) (reconcile.Result, error) {

	logger := accessRequestScope.Logger
	logger.V(logs.LogInfo).Info("Reconciling AccessRequest")

	if !controllerutil.ContainsFinalizer(accessRequestScope.AccessRequest, libsveltosv1alpha1.AccessRequestFinalizer) {
		if err := r.addFinalizer(ctx, accessRequestScope); err != nil {
			logger.V(logs.LogDebug).Info("failed to update finalizer")
			return reconcile.Result{}, err
		}
	}

	err := r.handleAccessRequest(ctx, accessRequestScope)
	if err != nil {
		failureMessage := err.Error()
		accessRequestScope.SetFailureMessage(&failureMessage)
		return reconcile.Result{}, err
	}

	logger.V(logs.LogInfo).Info("Reconcile success")
	// Requeue in expirationInSecond in order to renew token
	return reconcile.Result{Requeue: true, RequeueAfter: expirationInSecond}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AccessRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	_, err := ctrl.NewControllerManagedBy(mgr).
		For(&libsveltosv1alpha1.AccessRequest{}).
		WithEventFilter(IfNewDeletedOrSpecChange(mgr.GetLogger())).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.ConcurrentReconciles,
		}).
		Build(r)
	if err != nil {
		return errors.Wrap(err, "error creating controller")
	}
	return nil
}

func (r *AccessRequestReconciler) addFinalizer(ctx context.Context, accessRequestScope *scope.AccessRequestScope) error {
	// If the SveltosCluster doesn't have our finalizer, add it.
	controllerutil.AddFinalizer(accessRequestScope.AccessRequest, libsveltosv1alpha1.AccessRequestFinalizer)
	// Register the finalizer immediately to avoid orphaning accessRequest resources on delete
	if err := accessRequestScope.PatchObject(ctx); err != nil {
		accessRequestScope.Error(err, "Failed to add finalizer")
		return errors.Wrapf(
			err,
			"Failed to add finalizer for %s",
			accessRequestScope.Name(),
		)
	}
	return nil
}

func (r *AccessRequestReconciler) handleAccessRequest(ctx context.Context, accessRequestScope *scope.AccessRequestScope) error {
	// Create if not existing already, ServiceAccount
	err := r.createServiceAccount(ctx, accessRequestScope)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to create service account %v", err))
		return err
	}

	err = r.createRoleAndRoleBinding(ctx, accessRequestScope)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to create role and roleBinding %v", err))
		return err
	}

	var kubeconfig []byte
	kubeconfig, err = r.generateKubeconfig(ctx, accessRequestScope)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to generate kubeconfig %v", err))
		return err
	}

	err = r.updateSecret(ctx, accessRequestScope, kubeconfig)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to create/update secret with kubeconfig: %v", err))
		return err
	}

	accessRequestScope.Logger.V(logs.LogInfo).Info("set status secretref")
	accessRequestScope.SetSecretRef(&corev1.ObjectReference{
		Namespace:  accessRequestScope.AccessRequest.Spec.Namespace,
		Name:       accessRequestScope.AccessRequest.Spec.Name,
		Kind:       "Secret",
		APIVersion: "v1",
	})

	return nil
}

func (r *AccessRequestReconciler) generateKubeconfig(ctx context.Context, accessRequestScope *scope.AccessRequestScope) ([]byte, error) {
	// Get token for serviceAccount
	ar := accessRequestScope.AccessRequest
	expiration := int64(expirationInSecond.Seconds())
	treq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			// TODO: not setting it for now. Is it needed?
			// Audiences:         []string{"https://kubernetes.default.svc.cluster.local"},
			ExpirationSeconds: &expiration,
		},
	}

	clientset, err := kubernetes.NewForConfig(r.Config)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to create rest config: %v", err))
		return nil, err
	}

	var tokenRequest *authenticationv1.TokenRequest
	tokenRequest, err = clientset.CoreV1().ServiceAccounts(ar.Spec.Namespace).CreateToken(ctx, ar.Spec.Name, treq, metav1.CreateOptions{})
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to create token: %v", err))
		return nil, err
	}

	// Get Secret
	var crt []byte
	crt, err = r.getCACert(ctx)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to create token: %v", err))
		return nil, err
	}

	var kubeconfig []byte
	host := fmt.Sprintf("%s:%d", ar.Spec.ControlPlaneEndpoint.Host, ar.Spec.ControlPlaneEndpoint.Port)
	kubeconfig, err = libsveltosutils.GetKubeconfigWithUserToken(ctx, []byte(tokenRequest.Status.Token), crt, ar.Spec.Name, host)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get kubeconfig: %v", err))
		return nil, err
	}

	return kubeconfig, nil
}

func (r *AccessRequestReconciler) getCACert(ctx context.Context) ([]byte, error) {
	configMapNs := "kube-system"
	configMapName := "kube-root-ca.crt"
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Namespace: configMapNs, Name: configMapName}, configMap)
	if err != nil {
		return nil, err
	}

	if configMap.Data == nil {
		return nil, fmt.Errorf("configMap %s/%s Data section is nil", configMapNs, configMapName)
	}

	return []byte(configMap.Data["ca.crt"]), nil
}

// createServiceAccount creates a serviceAccount if it does not exist already
func (r *AccessRequestReconciler) createServiceAccount(ctx context.Context, accessRequestScope *scope.AccessRequestScope) error {
	ar := accessRequestScope.AccessRequest

	sa := &corev1.ServiceAccount{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ar.Spec.Namespace, Name: ar.Spec.Name}, sa)
	if err != nil {
		if apierrors.IsNotFound(err) {
			sa.Namespace = ar.Spec.Namespace
			sa.Name = ar.Spec.Name
			sa.Labels = map[string]string{libsveltosv1alpha1.AccessRequestNameLabel: ar.Name}
			return r.Create(ctx, sa)
		}
	}

	return nil
}

// createRoleAndRoleBinding creates a Role and RoleBinding
func (r *AccessRequestReconciler) createRoleAndRoleBinding(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope) error {

	ar := accessRequestScope.AccessRequest

	var rules []rbacv1.PolicyRule
	switch ar.Spec.Type {
	case libsveltosv1alpha1.SveltosAgentRequest:
		rules = r.getClassifierPolicyRules()
	default:
		return fmt.Errorf("unknow type %s", ar.Spec.Type)
	}

	err := r.createRole(ctx, accessRequestScope, rules)
	if err != nil {
		return err
	}

	err = r.createRoleBinding(ctx, accessRequestScope)
	if err != nil {
		return err
	}

	return nil
}

// createRole creates Role if it does not exist already
func (r *AccessRequestReconciler) createRole(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope, rules []rbacv1.PolicyRule) error {

	ar := accessRequestScope.AccessRequest

	role := &rbacv1.Role{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ar.Spec.Namespace, Name: ar.Spec.Name}, role)
	if err != nil {
		if apierrors.IsNotFound(err) {
			role.Namespace = ar.Spec.Namespace
			role.Name = ar.Spec.Name
			role.Labels = map[string]string{libsveltosv1alpha1.AccessRequestNameLabel: ar.Name}
			role.Rules = rules
			return r.Create(ctx, role)
		}
	}

	role.Namespace = ar.Spec.Namespace
	role.Name = ar.Spec.Name
	role.Rules = rules
	role.Labels = map[string]string{libsveltosv1alpha1.AccessRequestNameLabel: ar.Name}
	return r.Update(ctx, role)
}

// createRoleBinding creates RoleBinding if it does not exist already
func (r *AccessRequestReconciler) createRoleBinding(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope) error {

	ar := accessRequestScope.AccessRequest

	roleBinding := &rbacv1.RoleBinding{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ar.Spec.Namespace, Name: ar.Spec.Name}, roleBinding)
	if err != nil {
		if apierrors.IsNotFound(err) {
			roleBinding.Namespace = ar.Spec.Namespace
			roleBinding.Name = ar.Spec.Name
			roleBinding.Labels = map[string]string{libsveltosv1alpha1.AccessRequestNameLabel: ar.Name}
			roleBinding.RoleRef = rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     ar.Spec.Name,
			}
			roleBinding.Subjects = []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      ar.Spec.Name,
					Namespace: ar.Spec.Namespace,
				},
			}
			return r.Create(ctx, roleBinding)
		}
	}

	return nil
}

// getClassifierPolicyRules returns rule needed by ClassifierAgent
func (r *AccessRequestReconciler) getClassifierPolicyRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{
			APIGroups: []string{"lib.projectsveltos.io"},
			Resources: []string{"classifierreports"},
			Verbs:     []string{"create", "get", "list", "update"},
		},
		{
			APIGroups: []string{"lib.projectsveltos.io"},
			Resources: []string{"healthcheckreports"},
			Verbs:     []string{"create", "get", "list", "update"},
		},
		{
			APIGroups: []string{"lib.projectsveltos.io"},
			Resources: []string{"eventreports"},
			Verbs:     []string{"create", "get", "list", "update"},
		},
	}
}

func (r *AccessRequestReconciler) updateSecret(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope, kubeconfig []byte) error {

	ar := accessRequestScope.AccessRequest

	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ar.Spec.Namespace, Name: ar.Spec.Name}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			secret.Namespace = ar.Spec.Namespace
			secret.Name = ar.Spec.Name
			secret.Labels = map[string]string{libsveltosv1alpha1.AccessRequestNameLabel: ar.Name}
			secret.Data = map[string][]byte{"data": kubeconfig}
			return r.Create(ctx, secret)
		}
		return err
	}

	secret.Data = map[string][]byte{"data": kubeconfig}
	return r.Update(ctx, secret)
}

func (r *AccessRequestReconciler) cleanup(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope, logger logr.Logger) error {

	err := r.removeRole(ctx, accessRequestScope)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to remove role %v", err))
		return err
	}

	err = r.removeRoleBinding(ctx, accessRequestScope)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to remove roleBinding %v", err))
		return err
	}

	err = r.removeServiceAccount(ctx, accessRequestScope)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to remove serviceAccount %v", err))
		return err
	}

	err = r.removeSecret(ctx, accessRequestScope)
	if err != nil {
		accessRequestScope.Logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to remove secret %v", err))
		return err
	}

	return nil
}

func (r *AccessRequestReconciler) removeRole(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope) error {

	ar := accessRequestScope.AccessRequest
	role := &rbacv1.Role{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ar.Spec.Namespace, Name: ar.Spec.Name}, role)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, role)
}

func (r *AccessRequestReconciler) removeRoleBinding(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope) error {

	ar := accessRequestScope.AccessRequest
	roleBinding := &rbacv1.RoleBinding{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ar.Spec.Namespace, Name: ar.Spec.Name}, roleBinding)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, roleBinding)
}

func (r *AccessRequestReconciler) removeServiceAccount(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope) error {

	ar := accessRequestScope.AccessRequest
	sa := &corev1.ServiceAccount{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ar.Spec.Namespace, Name: ar.Spec.Name}, sa)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, sa)
}

func (r *AccessRequestReconciler) removeSecret(ctx context.Context,
	accessRequestScope *scope.AccessRequestScope) error {

	ar := accessRequestScope.AccessRequest
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ar.Spec.Namespace, Name: ar.Spec.Name}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, secret)
}
