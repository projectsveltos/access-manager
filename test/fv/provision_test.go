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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("AccessRequest: provision", func() {
	const (
		namePrefix = "provision-"
	)

	It("AccessRequest reconciler creates secret with kubeconfig", Label("FV"), func() {
		accessRequest := getAccessRequest(namePrefix)
		Expect(k8sClient.Create(context.TODO(), accessRequest)).To(Succeed())

		// The namespace is supposed to exist
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: accessRequest.Spec.Namespace,
			},
		}
		Expect(k8sClient.Create(context.TODO(), ns)).To(Succeed())

		verifyAccessRequest(accessRequest.Name)

		Byf("Deleting AccessRequest %s", accessRequest.Name)
		deleteAndVerifyCleanup(accessRequest.Name)
	})
})
