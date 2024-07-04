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

package fv_test

import (
	"context"
	"fmt"
	"unicode/utf8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/controller-runtime/pkg/client"

	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
)

const (
	key   = "env"
	value = "fv"
)

// Byf is a simple wrapper around By.
func Byf(format string, a ...interface{}) {
	By(fmt.Sprintf(format, a...)) // ignore_by_check
}

func randomString() string {
	const length = 10
	return util.RandomString(length)
}

func getAccessRequest(namePrefix string) *libsveltosv1beta1.AccessRequest {
	namespace := namePrefix + randomString()
	name := namePrefix + randomString()
	return &libsveltosv1beta1.AccessRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: libsveltosv1beta1.AccessRequestSpec{
			Namespace: namespace,
			Name:      name + "-classifier-agent",
			Type:      libsveltosv1beta1.SveltosAgentRequest,
			ControlPlaneEndpoint: clusterv1.APIEndpoint{
				Host: "https://192.168.10.22",
				Port: int32(6433),
			},
		},
	}
}

func verifyAccessRequest(accessRequest *libsveltosv1beta1.AccessRequest) {
	Byf("Verifing AccessRequest %s/%s", accessRequest.Namespace, accessRequest.Name)

	Byf("Get AccessRequest")
	Eventually(func() error {
		currentAccessRequest := &libsveltosv1beta1.AccessRequest{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name}, currentAccessRequest)
	}, timeout, pollingInterval).Should(BeNil())

	currentAccessRequest := &libsveltosv1beta1.AccessRequest{}
	Expect(k8sClient.Get(context.TODO(),
		types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name},
		currentAccessRequest)).To(Succeed())

	Byf("Verifying ServiceAccount")
	Eventually(func() error {
		sa := &corev1.ServiceAccount{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: currentAccessRequest.Spec.Name, Namespace: currentAccessRequest.Spec.Namespace}, sa)
	}, timeout, pollingInterval).Should(BeNil())

	Byf("Verifying Role")
	Eventually(func() error {
		role := &rbacv1.Role{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: currentAccessRequest.Spec.Name, Namespace: currentAccessRequest.Spec.Namespace}, role)
	}, timeout, pollingInterval).Should(BeNil())

	Byf("Verifying RoleBinding")
	Eventually(func() error {
		roleBinding := &rbacv1.RoleBinding{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: currentAccessRequest.Spec.Name, Namespace: currentAccessRequest.Spec.Namespace}, roleBinding)
	}, timeout, pollingInterval).Should(BeNil())

	Byf("Verifying Secret")
	Eventually(func() error {
		secret := &corev1.Secret{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: currentAccessRequest.Spec.Name, Namespace: currentAccessRequest.Spec.Namespace}, secret)
	}, timeout, pollingInterval).Should(BeNil())

	secret := &corev1.Secret{}
	Expect(k8sClient.Get(context.TODO(),
		types.NamespacedName{Name: currentAccessRequest.Spec.Name, Namespace: currentAccessRequest.Spec.Namespace}, secret)).To(Succeed())

	Expect(secret.Data).ToNot(BeNil())
	_, ok := secret.Data["data"]
	Expect(ok).To(BeTrue())

	Byf("Verifying AccessRequest Status")
	currentAccessRequest = &libsveltosv1beta1.AccessRequest{}
	Expect(k8sClient.Get(context.TODO(),
		types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name},
		currentAccessRequest)).To(Succeed())
	Expect(currentAccessRequest.Status.FailureMessage).To(BeNil())
	Expect(currentAccessRequest.Status.SecretRef).ToNot(BeNil())
}

func deleteAndVerifyCleanup(accessRequest *libsveltosv1beta1.AccessRequest) {
	Byf("Get AccessRequest")
	Eventually(func() error {
		currentAccessRequest := &libsveltosv1beta1.AccessRequest{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name}, currentAccessRequest)
	}, timeout, pollingInterval).Should(BeNil())

	currentAccessRequest := &libsveltosv1beta1.AccessRequest{}
	Expect(k8sClient.Get(context.TODO(),
		types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name},
		currentAccessRequest)).To(Succeed())
	Expect(k8sClient.Delete(context.TODO(), currentAccessRequest)).To(Succeed())

	Byf("Verifying ServiceAccount is gone")
	Eventually(func() bool {
		sa := &corev1.ServiceAccount{}
		err := k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, sa)
		return apierrors.IsNotFound(err)
	}, timeout, pollingInterval).Should(BeTrue())

	Byf("Verifying Role is gone")
	Eventually(func() bool {
		role := &rbacv1.Role{}
		err := k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, role)
		return apierrors.IsNotFound(err)
	}, timeout, pollingInterval).Should(BeTrue())

	Byf("Verifying RoleBinding is gone")
	Eventually(func() bool {
		roleBinding := &rbacv1.RoleBinding{}
		err := k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, roleBinding)
		return apierrors.IsNotFound(err)
	}, timeout, pollingInterval).Should(BeTrue())

	Byf("Verifying Secret is gone")
	Eventually(func() bool {
		secret := &corev1.Secret{}
		err := k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, secret)
		return apierrors.IsNotFound(err)
	}, timeout, pollingInterval).Should(BeTrue())
}

func getRoleRequest(namePrefix, saNamespace, saName string,
	clusterLabels map[string]string) *libsveltosv1beta1.RoleRequest {

	roleRequest := &libsveltosv1beta1.RoleRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: namePrefix + randomString(),
		},
		Spec: libsveltosv1beta1.RoleRequestSpec{
			ClusterSelector: libsveltosv1beta1.Selector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: clusterLabels,
				},
			},
			ServiceAccountNamespace: saNamespace,
			ServiceAccountName:      saName,
		},
	}

	return roleRequest
}

// createConfigMapWithPolicy creates a configMap with passed in policies.
func createConfigMapWithPolicy(namespace, configMapName string, policyStrs ...string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      configMapName,
		},
		Data: map[string]string{},
	}
	for i := range policyStrs {
		key := fmt.Sprintf("policy%d.yaml", i)
		if utf8.Valid([]byte(policyStrs[i])) {
			cm.Data[key] = policyStrs[i]
		} else {
			cm.BinaryData[key] = []byte(policyStrs[i])
		}
	}

	return cm
}

// getKindWorkloadClusterKubeconfig returns client to access the kind cluster used as workload cluster
func getKindWorkloadClusterKubeconfig() (client.Client, error) {
	kubeconfigPath := "workload_kubeconfig" // this file is created in this directory by Makefile during cluster creation
	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	restConfig, err := clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}
	return client.New(restConfig, client.Options{Scheme: scheme})
}

// getServiceAccountNameInManagedCluster returns the name of the ServiceAccount in the managed
// cluster.
// namespace, name are the namespace and name of the ServiceAccount in the management cluster
// for which a RoleRequest was created.
func getServiceAccountNameInManagedCluster(namespace, name string) string {
	// A RoleRequest contains the Namespace/Name of the ServiceAccount in the management
	// cluster for which a RoleRequest was issued (request to grant permission in managed clusters).
	// When processing a RoleRequest, Sveltos creates a ServiceAccount in the managed cluster.
	// Such ServiceAccount is created in the "projectsveltos" namespace.
	// This method returns the name of the ServiceAccount in the managed cluster (name cannot
	// match the one in the management cluster to avoid clashes)
	return fmt.Sprintf("%s--%s", namespace, name)
}
