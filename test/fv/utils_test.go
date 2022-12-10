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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util"

	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
)

// Byf is a simple wrapper around By.
func Byf(format string, a ...interface{}) {
	By(fmt.Sprintf(format, a...)) // ignore_by_check
}

func randomString() string {
	const length = 10
	return util.RandomString(length)
}

func getAccessRequest(namePrefix string) *libsveltosv1alpha1.AccessRequest {
	namespace := namePrefix + randomString()
	name := namePrefix + randomString()
	return &libsveltosv1alpha1.AccessRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: libsveltosv1alpha1.AccessRequestSpec{
			Namespace: namespace,
			Name:      name + "-classifier-agent",
			Type:      libsveltosv1alpha1.ClassifierAgentRequest,
			ControlPlaneEndpoint: clusterv1.APIEndpoint{
				Host: "https://192.168.10.22",
				Port: int32(6433),
			},
		},
	}
}

func verifyAccessRequest(accessRequest *libsveltosv1alpha1.AccessRequest) {
	Byf("Verifing AccessRequest %s/%s", accessRequest.Namespace, accessRequest.Name)

	Byf("Get AccessRequest")
	Eventually(func() error {
		currentAccessRequest := &libsveltosv1alpha1.AccessRequest{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name}, currentAccessRequest)
	}, timeout, pollingInterval).Should(BeNil())

	currentAccessRequest := &libsveltosv1alpha1.AccessRequest{}
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
	currentAccessRequest = &libsveltosv1alpha1.AccessRequest{}
	Expect(k8sClient.Get(context.TODO(),
		types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name},
		currentAccessRequest)).To(Succeed())
	Expect(currentAccessRequest.Status.FailureMessage).To(BeNil())
	Expect(currentAccessRequest.Status.SecretRef).ToNot(BeNil())
}

func deleteAndVerifyCleanup(accessRequest *libsveltosv1alpha1.AccessRequest) {
	Byf("Get AccessRequest")
	Eventually(func() error {
		currentAccessRequest := &libsveltosv1alpha1.AccessRequest{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name}, currentAccessRequest)
	}, timeout, pollingInterval).Should(BeNil())

	currentAccessRequest := &libsveltosv1alpha1.AccessRequest{}
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
