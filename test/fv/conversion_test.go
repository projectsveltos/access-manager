/*
Copyright 2024. projectsveltos.io. All rights reserved.

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
)

var _ = Describe("RoleRequest Conversion", func() {
	const (
		namePrefix = "conversion-"
	)

	It("Post a RoleRequest.v1alpha1 and verify all is deployed", Label("FV"), func() {
		Byf("Create a RoleRequest matching Cluster %s/%s", kindWorkloadCluster.Namespace, kindWorkloadCluster.Name)
		saNamespace := randomString()
		saName := randomString()

		v1alpha1RoleRequest := &libsveltosv1alpha1.RoleRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: namePrefix + randomString(),
			},
			Spec: libsveltosv1alpha1.RoleRequestSpec{
				ClusterSelector:         libsveltosv1alpha1.Selector(fmt.Sprintf("%s=%s", key, value)),
				ServiceAccountNamespace: saNamespace,
				ServiceAccountName:      saName,
			},
		}
		Expect(k8sClient.Create(context.TODO(), v1alpha1RoleRequest)).To(Succeed())

		v1beta1RoleRequest := &libsveltosv1beta1.RoleRequest{}
		Expect(k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: v1alpha1RoleRequest.Name}, v1beta1RoleRequest)).To(Succeed())
		Expect(len(v1beta1RoleRequest.Spec.ClusterSelector.LabelSelector.MatchLabels)).To(Equal(1))
		Expect(v1beta1RoleRequest.Spec.ClusterSelector.LabelSelector.MatchLabels[key]).To(Equal(value))

		namespace := randomString()
		roleName := randomString()
		editRole := fmt.Sprintf(editRoleTemplate, roleName, namespace)

		configMapNs := randomString()
		Byf("Create configMap's namespace %s", configMapNs)
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: configMapNs,
			},
		}
		Expect(k8sClient.Create(context.TODO(), ns)).To(Succeed())

		Byf("Create a configMap with a Role")
		configMap := createConfigMapWithPolicy(configMapNs, namePrefix+randomString(), editRole)
		Expect(k8sClient.Create(context.TODO(), configMap)).To(Succeed())
		currentConfigMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(context.TODO(),
			types.NamespacedName{Namespace: configMap.Namespace, Name: configMap.Name}, currentConfigMap)).To(Succeed())

		Byf("Update RoleRequest %s to reference ConfigMap %s/%s", v1alpha1RoleRequest.Name, configMap.Namespace, configMap.Name)
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}
			Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: v1alpha1RoleRequest.Name}, currentRoleRequest)).To(Succeed())
			currentRoleRequest.Spec.RoleRefs = []libsveltosv1alpha1.PolicyRef{
				{
					Kind:      string(libsveltosv1alpha1.ConfigMapReferencedResourceKind),
					Namespace: configMap.Namespace,
					Name:      configMap.Name,
				},
			}
			return k8sClient.Update(context.TODO(), currentRoleRequest)
		})
		Expect(err).To(BeNil())

		Byf("Getting client to access the workload cluster")
		workloadClient, err := getKindWorkloadClusterKubeconfig()
		Expect(err).To(BeNil())
		Expect(workloadClient).ToNot(BeNil())

		Byf("Verifying proper Role is created in the workload cluster")
		Eventually(func() error {
			currentRole := &rbacv1.Role{}
			return workloadClient.Get(context.TODO(),
				types.NamespacedName{Namespace: namespace, Name: roleName}, currentRole)
		}, timeout, pollingInterval).Should(BeNil())

		currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}
		By(fmt.Sprintf("Deleting RoleRequest %s", v1alpha1RoleRequest.Name))
		Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: v1alpha1RoleRequest.Name},
			currentRoleRequest)).To(Succeed())
		Expect(k8sClient.Delete(context.TODO(), currentRoleRequest)).To(Succeed())

		By(fmt.Sprintf("Verifying RoleRequest %s is not found anymore", roleName))
		Eventually(func() bool {
			err = k8sClient.Get(context.TODO(), types.NamespacedName{Name: roleName},
				currentRoleRequest)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())
	})
})
