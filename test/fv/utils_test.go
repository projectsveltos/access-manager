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
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/controller-runtime/pkg/client"

	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
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

func getAccessRequest(namePrefix string) *libsveltosv1alpha1.AccessRequest {
	return &libsveltosv1alpha1.AccessRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: namePrefix + randomString(),
		},
		Spec: libsveltosv1alpha1.AccessRequestSpec{
			Namespace: randomString(),
			Name:      randomString(),
			Type:      libsveltosv1alpha1.ClassifierAgentRequest,
		},
	}
}

func verifyAccessRequest(accessRequestName string) {
	Byf("Verifing AccessRequest %s", accessRequestName)

	Byf("Get AccessRequest")
	Eventually(func() error {
		accessRequest := &libsveltosv1alpha1.AccessRequest{}
		return k8sClient.Get(context.TODO(), types.NamespacedName{Name: accessRequestName}, accessRequest)
	}, timeout, pollingInterval).Should(BeNil())

	accessRequest := &libsveltosv1alpha1.AccessRequest{}
	Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: accessRequestName}, accessRequest)).To(Succeed())

	Byf("Verifying ServiceAccount")
	Eventually(func() error {
		sa := &corev1.ServiceAccount{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, sa)
	}, timeout, pollingInterval).Should(BeNil())

	Byf("Verifying Role")
	Eventually(func() error {
		role := &rbacv1.Role{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, role)
	}, timeout, pollingInterval).Should(BeNil())

	Byf("Verifying RoleBinding")
	Eventually(func() error {
		roleBinding := &rbacv1.RoleBinding{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, roleBinding)
	}, timeout, pollingInterval).Should(BeNil())

	Byf("Verifying Secret")
	Eventually(func() error {
		secret := &corev1.Secret{}
		return k8sClient.Get(context.TODO(),
			types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, secret)
	}, timeout, pollingInterval).Should(BeNil())

	secret := &corev1.Secret{}
	Expect(k8sClient.Get(context.TODO(),
		types.NamespacedName{Name: accessRequest.Spec.Name, Namespace: accessRequest.Spec.Namespace}, secret)).To(Succeed())

	Expect(secret.Data).ToNot(BeNil())
	_, ok := secret.Data["data"]
	Expect(ok).To(BeTrue())

	Byf("Verifying AccessRequest Status")
	accessRequest = &libsveltosv1alpha1.AccessRequest{}
	Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: accessRequestName}, accessRequest)).To(Succeed())
	Expect(accessRequest.Status.FailureMessage).To(BeNil())
	Expect(accessRequest.Status.SecretRef).ToNot(BeNil())
}

func deleteAndVerifyCleanup(accessRequestName string) {
	Byf("Get AccessRequest")
	Eventually(func() error {
		accessRequest := &libsveltosv1alpha1.AccessRequest{}
		return k8sClient.Get(context.TODO(), types.NamespacedName{Name: accessRequestName}, accessRequest)
	}, timeout, pollingInterval).Should(BeNil())

	accessRequest := &libsveltosv1alpha1.AccessRequest{}
	Expect(k8sClient.Get(context.TODO(), types.NamespacedName{Name: accessRequestName}, accessRequest)).To(Succeed())
	Expect(k8sClient.Delete(context.TODO(), accessRequest)).To(Succeed())

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

// getKubeconfigForAccessRequest waits for AccessRequest to be fulfilled and return
// corresponding kubeconfig
func getKubeconfigForAccessRequest(accessRequest *libsveltosv1alpha1.AccessRequest) []byte {
	Expect(accessRequest).ToNot(BeNil())

	accessRequestInfo := client.ObjectKey{Name: accessRequest.Name}

	Eventually(func() bool {
		currentAccessRequest := &libsveltosv1alpha1.AccessRequest{}
		err := k8sClient.Get(context.TODO(), accessRequestInfo, currentAccessRequest)
		return err == nil &&
			currentAccessRequest.Status.SecretRef != nil
	}, timeout, pollingInterval).Should(BeNil())

	currentAccessRequest := &libsveltosv1alpha1.AccessRequest{}
	Expect(k8sClient.Get(context.TODO(), accessRequestInfo, currentAccessRequest)).To(Succeed())

	secret := &corev1.Secret{}
	Expect(k8sClient.Get(context.TODO(),
		types.NamespacedName{Name: currentAccessRequest.Status.SecretRef.Name, Namespace: currentAccessRequest.Status.SecretRef.Namespace},
		secret)).To(Succeed())

	Expect(secret.Data).ToNot(BeNil())
	_, ok := secret.Data["data"]
	Expect(ok).To(BeTrue())

	return secret.Data["data"]
}
