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
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	apiv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	"github.com/projectsveltos/libsveltos/lib/deployer"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
	libsveltosroles "github.com/projectsveltos/libsveltos/lib/roles"
	"github.com/projectsveltos/libsveltos/lib/utils"
	libsveltosutils "github.com/projectsveltos/libsveltos/lib/utils"
)

const (
	separator               = "---\n"
	serviceAccountNamespace = "projectsveltos"
	roleKind                = "Role"
	clusterRoleKind         = "ClusterRole"
	// expirationInSecond is the token expiration time.
	saExpirationInSecond = 365 * 24 * 60 * time.Minute
)

// createServiceAccountInManagedCluster create a ServiceAccount with passed in name in the
// projectsveltos namespace
func createServiceAccountInManagedCluster(ctx context.Context, remoteClient client.Client,
	roleRequest *libsveltosv1alpha1.RoleRequest) error {

	err := createNamespaceInManagedCluster(ctx, remoteClient, serviceAccountNamespace)
	if err != nil {
		return err
	}

	serviceAccount := &corev1.ServiceAccount{}
	err = remoteClient.Get(ctx, client.ObjectKey{Namespace: serviceAccountNamespace, Name: roleRequest.Spec.Admin},
		serviceAccount)
	if err != nil {
		if apierrors.IsNotFound(err) {
			serviceAccount.Namespace = serviceAccountNamespace
			serviceAccount.Name = roleRequest.Spec.Admin
			serviceAccount.Labels = map[string]string{libsveltosv1alpha1.RoleRequestLabel: "ok"}
			deployer.AddOwnerReference(serviceAccount, roleRequest)
			return remoteClient.Create(ctx, serviceAccount)
		}
		return err
	}
	deployer.AddOwnerReference(serviceAccount, roleRequest)
	return remoteClient.Update(ctx, serviceAccount)
}

// getServiceAccountToken returns token for a serviceaccount
func getServiceAccountToken(ctx context.Context, config *rest.Config, saName string) ([]byte, error) {
	// Get token for serviceAccount
	expiration := int64(saExpirationInSecond.Seconds())
	treq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &expiration,
		},
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	var tokenRequest *authenticationv1.TokenRequest
	tokenRequest, err = clientset.CoreV1().ServiceAccounts(serviceAccountNamespace).CreateToken(ctx, saName, treq, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return []byte(tokenRequest.Status.Token), nil
}

func createServiceAccountSecretForCluster(ctx context.Context, config *rest.Config, c client.Client,
	clusterNamespace, clusterName, serviceAccountName string, clusterType libsveltosv1alpha1.ClusterType,
	roleRequest *libsveltosv1alpha1.RoleRequest, logger logr.Logger) error {

	logger = logger.WithValues("serviceaccount", serviceAccountName)
	logger = logger.WithValues("cluster", fmt.Sprintf("%s/%s", clusterNamespace, clusterName))

	token, err := getServiceAccountToken(ctx, config, serviceAccountName)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get token for serviceaccount. Err: %v", err))
		return err
	}

	var kubeconfigContent []byte
	kubeconfigContent, err = getSecretData(ctx, c, clusterNamespace, clusterName, clusterType, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get kubeconfig for cluster. Err: %v", err))
		return err
	}

	var u *unstructured.Unstructured
	u, err = libsveltosutils.GetUnstructured(kubeconfigContent)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to unstructured for kind Config. Err: %v", err))
		return err
	}

	configObject := apiv1.Config{}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(u.UnstructuredContent(), &configObject)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to convert unstructured to kind Config. Err: %v", err))
		return err
	}

	if configObject.Clusters == nil || len(configObject.Clusters) > 1 {
		logger.V(logs.LogInfo).Info("malformed configObject.Clusters")
		return err
	}

	caCrt := configObject.Clusters[0].Cluster.CertificateAuthorityData
	server := configObject.Clusters[0].Cluster.Server

	var kubeconfig []byte
	kubeconfig, err = libsveltosutils.GetKubeconfigWithUserToken(ctx, token, caCrt, serviceAccountName, server)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to get kubeconfig: %v", err))
		return err
	}

	return createSecretWithKubeconfig(ctx, c, roleRequest, clusterNamespace, clusterName, serviceAccountName,
		clusterType, kubeconfig, logger)
}

func createSecretWithKubeconfig(ctx context.Context, c client.Client, roleRequest *libsveltosv1alpha1.RoleRequest,
	clusterNamespace, clusterName, serviceAccountName string,
	clusterType libsveltosv1alpha1.ClusterType, kubeconfig []byte, logger logr.Logger) error {

	_, err := libsveltosroles.CreateSecret(ctx, c, clusterNamespace, clusterName, serviceAccountName,
		clusterType, kubeconfig, roleRequest)
	if err != nil {
		logger.V(logs.LogInfo).Info("failed to create secret %v", err)
		return err
	}

	return nil
}

// createNamespaceInManagedCluster creates a namespace if it does not exist already
// No action in DryRun mode.
func createNamespaceInManagedCluster(ctx context.Context, remoteClient client.Client,
	namespaceName string) error {

	if namespaceName == "" {
		return nil
	}

	currentNs := &corev1.Namespace{}
	if err := remoteClient.Get(ctx, client.ObjectKey{Name: namespaceName}, currentNs); err != nil {
		if apierrors.IsNotFound(err) {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespaceName,
				},
			}
			return remoteClient.Create(ctx, ns)
		}
		return err
	}
	return nil
}

// collectReferencedObjects collects all referenced configMaps/secrets in control cluster
func collectReferencedObjects(ctx context.Context, c client.Client,
	references []libsveltosv1alpha1.PolicyRef, logger logr.Logger) ([]client.Object, error) {

	objects := make([]client.Object, 0)
	for i := range references {
		var err error
		var object client.Object
		reference := &references[i]
		if reference.Kind == string(libsveltosv1alpha1.ConfigMapReferencedResourceKind) {
			object, err = getConfigMap(ctx, c,
				types.NamespacedName{Namespace: reference.Namespace, Name: reference.Name})
		} else {
			object, err = getSecret(ctx, c,
				types.NamespacedName{Namespace: reference.Namespace, Name: reference.Name})
		}
		if err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(logs.LogInfo).Info(fmt.Sprintf("%s %s/%s does not exist yet",
					reference.Kind, reference.Namespace, reference.Name))
				continue
			}
			return nil, err
		}
		objects = append(objects, object)
	}

	return objects, nil
}

// getConfigMap retrieves any ConfigMap from the given name and namespace.
func getConfigMap(ctx context.Context, c client.Client, configmapName types.NamespacedName) (*corev1.ConfigMap, error) {
	configMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: configmapName.Namespace,
		Name:      configmapName.Name,
	}
	if err := c.Get(ctx, configMapKey, configMap); err != nil {
		return nil, err
	}

	return configMap, nil
}

// getSecret retrieves any Secret from the given secret name and namespace.
func getSecret(ctx context.Context, c client.Client, secretName types.NamespacedName) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: secretName.Namespace,
		Name:      secretName.Name,
	}
	if err := c.Get(ctx, secretKey, secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func deployReferencedResourceInManagedCluster(ctx context.Context, remoteRestConfig *rest.Config, remoteClient client.Client,
	referencedResource client.Object, roleRequest *libsveltosv1alpha1.RoleRequest, logger logr.Logger,
) ([]corev1.ObjectReference, error) {

	var deployedResources []corev1.ObjectReference
	var err error
	switch referencedResource.GetObjectKind().GroupVersionKind().Kind {
	case "ConfigMap":
		configMap := referencedResource.(*corev1.ConfigMap)
		l := logger.WithValues("configMapNamespace", configMap.Namespace, "configMapName", configMap.Name)
		l.V(logs.LogDebug).Info("deploying ConfigMap content")
		deployedResources, err = deployContentOfConfigMap(ctx, remoteRestConfig, remoteClient, configMap, roleRequest, l)
	case "Secret":
		secret := referencedResource.(*corev1.Secret)
		l := logger.WithValues("secretNamespace", secret.Namespace, "secretName", secret.Name)
		l.V(logs.LogDebug).Info("deploying Secret content")
		deployedResources, err = deployContentOfSecret(ctx, remoteRestConfig, remoteClient, secret, roleRequest, l)
	}
	return deployedResources, err
}

// deployContentOfConfigMap deploys ClusterRoles/Roles contained in a ConfigMap.
// Returns an error if one occurred.
func deployContentOfConfigMap(ctx context.Context, remoteConfig *rest.Config, remoteClient client.Client,
	configMap *corev1.ConfigMap, roleRequest *libsveltosv1alpha1.RoleRequest, logger logr.Logger,
) ([]corev1.ObjectReference, error) {

	return deployContent(ctx, remoteConfig, remoteClient, configMap, configMap.Data, roleRequest, logger)
}

// deployContentOfSecret deploys ClusterRoles/Roles contained in a Secret.
// Returns an error if one occurred. Otherwise it returns a slice containing the name of
// the policies deployed in the form of kind.group:namespace:name for namespaced policies
// and kind.group::name for cluster wide policies.
func deployContentOfSecret(ctx context.Context, remoteConfig *rest.Config, remoteClient client.Client,
	secret *corev1.Secret, roleRequest *libsveltosv1alpha1.RoleRequest, logger logr.Logger,
) ([]corev1.ObjectReference, error) {

	var err error
	data := make(map[string]string)
	for key, value := range secret.Data {
		data[key], err = decode(value)
		if err != nil {
			return nil, err
		}
	}

	return deployContent(ctx, remoteConfig, remoteClient, secret, data, roleRequest, logger)
}

func decode(encoded []byte) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

// deployContent deploys ClusterRoles/Roles contained in a ConfigMap/Secret.
// data might have one or more keys. Each key might contain a single policy
// or multiple policies separated by '---'
// Returns an error if one occurred.
func deployContent(ctx context.Context, remoteConfig *rest.Config, remoteClient client.Client,
	referencedObject client.Object, data map[string]string, roleRequest *libsveltosv1alpha1.RoleRequest,
	logger logr.Logger) ([]corev1.ObjectReference, error) {

	deployedPolicies := make([]corev1.ObjectReference, 0)

	referencedPolicies, err := collectContent(data, logger)
	if err != nil {
		logger.V(logs.LogInfo).Info(fmt.Sprintf("failed to collect content: %v", err))
		return nil, err
	}

	for i := range referencedPolicies {
		policy := referencedPolicies[i]

		if !isClusterRoleOrRole(policy, logger) {
			logger.V(logs.LogInfo).Info("Resource %s %s:%s is not ClusterRole/Role",
				policy.GetKind(), policy.GetNamespace(), policy.GetName())
			continue
		}

		var tmp []corev1.ObjectReference
		tmp, err = deployRole(ctx, remoteConfig, remoteClient, policy, referencedObject, roleRequest, logger)
		if err != nil {
			return nil, err
		}

		deployedPolicies = append(deployedPolicies, tmp...)
	}

	return deployedPolicies, nil
}

func deployRole(ctx context.Context, remoteConfig *rest.Config, remoteClient client.Client,
	policy *unstructured.Unstructured, referencedObject client.Object, roleRequest *libsveltosv1alpha1.RoleRequest,
	logger logr.Logger) ([]corev1.ObjectReference, error) {

	// Following labels are added to indentify ConfigMap/Secret causing this resource to be deployed.
	// Those are used to identify conflicts (different ConfigMaps/Secrets) updating same resource.
	// Note, it is possible and OK for different RoleRequest to reference same ConfigMap/Secret.
	addLabel(policy, deployer.ReferenceLabelKind, referencedObject.GetObjectKind().GroupVersionKind().Kind)
	addLabel(policy, deployer.ReferenceLabelName, referencedObject.GetName())
	addLabel(policy, deployer.ReferenceLabelNamespace, referencedObject.GetNamespace())

	addLabel(policy, libsveltosv1alpha1.RoleRequestLabel, "ok")

	// If policy is namespaced, create namespace if not already existing
	err := createNamespaceInManagedCluster(ctx, remoteClient, policy.GetNamespace())
	if err != nil {
		return nil, err
	}

	// If policy already exists, just get current version and update it by overridding
	// all metadata and spec.
	// If policy does not exist already, create it
	dr, err := utils.GetDynamicResourceInterface(remoteConfig, policy.GroupVersionKind(), policy.GetNamespace())
	if err != nil {
		return nil, err
	}

	_, _, err = deployer.ValidateObjectForUpdate(ctx, dr, policy,
		referencedObject.GetObjectKind().GroupVersionKind().Kind, referencedObject.GetNamespace(), referencedObject.GetName())
	if err != nil {
		return nil, err
	}

	deployer.AddOwnerReference(policy, roleRequest)

	err = updateResource(ctx, dr, policy, logger)
	if err != nil {
		return nil, err
	}

	roleRef := corev1.ObjectReference{
		Name:      policy.GetName(),
		Namespace: policy.GetNamespace(),
		Kind:      policy.GetKind(),
	}

	// Create corresponding ClusterRoleBinding/RoleBinding
	if policy.GetKind() == roleKind {
		var roleBindingRef *corev1.ObjectReference
		roleBindingRef, err = deployRoleBinding(ctx, remoteClient, policy, roleRequest, logger)
		return []corev1.ObjectReference{roleRef, *roleBindingRef}, err
	}

	var clusterRoleBindingRef *corev1.ObjectReference
	clusterRoleBindingRef, err = deployClusterRoleBinding(ctx, remoteClient, policy, roleRequest, logger)
	return []corev1.ObjectReference{roleRef, *clusterRoleBindingRef}, err
}

func deployRoleBinding(ctx context.Context, remoteClient client.Client,
	role *unstructured.Unstructured, roleRequest *libsveltosv1alpha1.RoleRequest,
	logger logr.Logger) (*corev1.ObjectReference, error) {

	roleBinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: role.GetNamespace(),
			Name:      role.GetName(),
			Labels:    map[string]string{libsveltosv1alpha1.RoleRequestLabel: "ok"},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     roleKind,
			Name:     role.GetName(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      roleRequest.Spec.Admin,
				Namespace: serviceAccountNamespace,
			},
		},
	}

	roleBindingRef := &corev1.ObjectReference{
		Name:      roleBinding.Name,
		Namespace: roleBinding.Namespace,
		Kind:      roleKind,
	}

	currentRoleBinding := &rbacv1.RoleBinding{}
	err := remoteClient.Get(ctx, types.NamespacedName{Namespace: roleBinding.Namespace, Name: roleBinding.Name},
		currentRoleBinding)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(logs.LogDebug).Info("creating roleBinding")
			return roleBindingRef, remoteClient.Create(ctx, &roleBinding)
		}
		return nil, err
	}

	currentRoleBinding.RoleRef = roleBinding.RoleRef
	currentRoleBinding.Subjects = roleBinding.Subjects
	currentRoleBinding.Labels = map[string]string{libsveltosv1alpha1.RoleRequestLabel: "ok"}
	logger.V(logs.LogDebug).Info("updating roleBinding")
	return roleBindingRef, remoteClient.Update(ctx, currentRoleBinding)
}

func deployClusterRoleBinding(ctx context.Context, remoteClient client.Client,
	clusterRole *unstructured.Unstructured, roleRequest *libsveltosv1alpha1.RoleRequest,
	logger logr.Logger) (*corev1.ObjectReference, error) {

	clusterRoleBinding := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   clusterRole.GetName(),
			Labels: map[string]string{libsveltosv1alpha1.RoleRequestLabel: "ok"},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     clusterRoleKind,
			Name:     clusterRole.GetName(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      roleRequest.Spec.Admin,
				Namespace: serviceAccountNamespace,
			},
		},
	}

	clusterRoleBindingRef := &corev1.ObjectReference{
		Name:      clusterRoleBinding.Name,
		Namespace: clusterRoleBinding.Namespace,
		Kind:      clusterRoleKind,
	}

	currentClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	err := remoteClient.Get(ctx,
		types.NamespacedName{Namespace: clusterRoleBinding.Namespace, Name: clusterRoleBinding.Name},
		currentClusterRoleBinding)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(logs.LogDebug).Info("creating clusteRoleBinding")
			return clusterRoleBindingRef, remoteClient.Create(ctx, &clusterRoleBinding)
		}
		return nil, err
	}

	currentClusterRoleBinding.RoleRef = clusterRoleBinding.RoleRef
	currentClusterRoleBinding.Subjects = clusterRoleBinding.Subjects
	currentClusterRoleBinding.Labels = map[string]string{libsveltosv1alpha1.RoleRequestLabel: "ok"}
	logger.V(logs.LogDebug).Info("updating clusteRoleBinding")
	return clusterRoleBindingRef, remoteClient.Update(ctx, currentClusterRoleBinding)
}

// collectContent collect policies contained in a ConfigMap/Secret.
// ConfigMap/Secret Data might have one or more keys. Each key might contain a single policy
// or multiple policies separated by '---'
// Returns an error if one occurred. Otherwise it returns a slice of *unstructured.Unstructured.
func collectContent(data map[string]string, logger logr.Logger) ([]*unstructured.Unstructured, error) {
	policies := make([]*unstructured.Unstructured, 0)

	for k := range data {
		elements := strings.Split(data[k], separator)
		for i := range elements {
			if elements[i] == "" {
				continue
			}

			policy, err := utils.GetUnstructured([]byte(elements[i]))
			if err != nil {
				logger.Error(err, fmt.Sprintf("failed to get policy from Data %.100s", elements[i]))
				return nil, err
			}

			if policy == nil {
				logger.Error(err, fmt.Sprintf("failed to get policy from Data %.100s", elements[i]))
				return nil, fmt.Errorf("failed to get policy from Data %.100s", elements[i])
			}

			policies = append(policies, policy)
		}
	}

	return policies, nil
}

// addLabel adds label to an object
func addLabel(obj metav1.Object, labelKey, labelValue string) {
	labels := obj.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels[labelKey] = labelValue
	obj.SetLabels(labels)
}

// updateResource creates or updates a resource in a CAPI Cluster.
// No action in DryRun mode.
func updateResource(ctx context.Context, dr dynamic.ResourceInterface,
	object *unstructured.Unstructured, logger logr.Logger) error {

	l := logger.WithValues("resourceNamespace", object.GetNamespace(),
		"resourceName", object.GetName(), "resourceGVK", object.GetObjectKind().GroupVersionKind())
	l.V(logs.LogDebug).Info("deploying policy")

	data, err := runtime.Encode(unstructured.UnstructuredJSONScheme, object)
	if err != nil {
		return err
	}

	forceConflict := true
	options := metav1.PatchOptions{
		FieldManager: "application/apply-patch",
		Force:        &forceConflict,
	}
	_, err = dr.Patch(ctx, object.GetName(), types.ApplyPatchType, data, options)
	return err
}

// isClusterRoleOrRole validates that resource being deployed is a ClusterRole/Role
func isClusterRoleOrRole(resource client.Object, logger logr.Logger) bool {
	logger = logger.WithValues("kind", resource.GetObjectKind(), "resource-namespace", resource.GetNamespace(),
		"resource-name", resource.GetName())

	if resource.GetObjectKind().GroupVersionKind().Group != "rbac.authorization.k8s.io" {
		logger.V(logs.LogInfo).Info("resource is not a ClusterRole/Role")
		return false
	}

	if resource.GetObjectKind().GroupVersionKind().Kind != clusterRoleKind &&
		resource.GetObjectKind().GroupVersionKind().Kind != roleKind {

		logger.V(logs.LogInfo).Info("resource is not a ClusterRole/Role")
		return false
	}

	return true
}
