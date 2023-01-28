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
	libsveltosroles "github.com/projectsveltos/libsveltos/lib/roles"
)

const (
	editRoleTemplate = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %s
  namespace: %s
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["*"]`
)

var _ = Describe("RoleRequest", func() {
	const (
		namePrefix = "rolerequest-"
	)

	It("Deploy and updates roles", Label("FV"), func() {
		Byf("Create a RoleRequest matching Cluster %s/%s", kindWorkloadCluster.Namespace, kindWorkloadCluster.Name)
		admin := randomString()
		roleRequest := getRoleRequest(namePrefix, admin, map[string]string{key: value})
		Expect(k8sClient.Create(context.TODO(), roleRequest)).To(Succeed())

		Byf("Update RoleRequest %s to deploy roles for admin %s", roleRequest.Name, admin)
		currentRolRequest := &libsveltosv1alpha1.RoleRequest{}
		Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name}, currentRolRequest)).To(Succeed())

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

		Byf("Update RoleRequest %s to reference ConfigMap %s/%s", roleRequest.Name, configMap.Namespace, configMap.Name)
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}
			Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name}, currentRoleRequest)).To(Succeed())
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

		Byf("Verifying proper RoleBinding is created in the workload cluster")
		currentRoleBinding := &rbacv1.RoleBinding{}
		Expect(workloadClient.Get(context.TODO(),
			types.NamespacedName{Namespace: namespace, Name: roleName}, currentRoleBinding)).To(Succeed())

		Expect(currentRoleBinding.RoleRef.Name).To(Equal(roleName))
		Expect(currentRoleBinding.RoleRef.Kind).To(Equal("Role"))
		Expect(currentRoleBinding.Subjects).ToNot(BeNil())
		Expect(len(currentRoleBinding.Subjects)).To(Equal(1))
		Expect(currentRoleBinding.Subjects[0].Name).To(Equal(admin))

		Byf("Verifying proper ServiceAccount is created in the workload cluster")
		currentServiceAccount := &corev1.ServiceAccount{}
		Expect(workloadClient.Get(context.TODO(),
			types.NamespacedName{Namespace: "projectsveltos", Name: admin}, currentServiceAccount)).To(Succeed())

		By(fmt.Sprintf("Verifying Secret for ServiceAccount %s Cluster %s/%s is created in the management cluster",
			admin, kindWorkloadCluster.Namespace, kindWorkloadCluster.Name))
		saSecret, err := libsveltosroles.GetSecret(context.TODO(), k8sClient, kindWorkloadCluster.Namespace, kindWorkloadCluster.Name,
			admin, libsveltosv1alpha1.ClusterTypeCapi)
		Expect(err).To(BeNil())
		Expect(saSecret).ToNot(BeNil())

		currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}

		By(fmt.Sprintf("Deleting RoleRequest %s", roleRequest.Name))
		Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name}, currentRoleRequest)).To(Succeed())
		Expect(k8sClient.Delete(context.TODO(), currentRolRequest)).To(Succeed())

		By(fmt.Sprintf("Verifying RoleRequest %s is not found anymore", roleRequest.Name))
		Eventually(func() bool {
			err = k8sClient.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name}, currentRoleRequest)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())

		Byf("Verifying Role is removed from the workload cluster")
		currentRole := &rbacv1.Role{}
		err = workloadClient.Get(context.TODO(),
			types.NamespacedName{Namespace: namespace, Name: roleName}, currentRole)
		Expect(err).ToNot(BeNil())
		Expect(apierrors.IsNotFound(err)).To(BeTrue())

		Byf("Verifying RoleBinding is removed from the workload cluster")
		err = workloadClient.Get(context.TODO(),
			types.NamespacedName{Namespace: namespace, Name: roleName}, currentRoleBinding)
		Expect(err).ToNot(BeNil())
		Expect(apierrors.IsNotFound(err)).To(BeTrue())

		Byf("Verifying ServiceAccount is removed from the workload cluster")
		err = workloadClient.Get(context.TODO(),
			types.NamespacedName{Namespace: "projectsveltos", Name: admin}, currentServiceAccount)
		Expect(err).ToNot(BeNil())
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})
})
