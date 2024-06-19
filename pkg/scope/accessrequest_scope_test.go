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

package scope_test

import (
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectsveltos/access-manager/pkg/scope"
	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
)

const (
	classifierNamePrefix  = "scope-"
	failedToDeploy        = "failed to deploy"
	apiserverNotReachable = "apiserver not reachable"
)

var _ = Describe("AccessRequestScope", func() {
	var accessRequest *libsveltosv1beta1.AccessRequest
	var c client.Client
	var logger logr.Logger

	BeforeEach(func() {
		logger = textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1)))

		accessRequest = &libsveltosv1beta1.AccessRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: classifierNamePrefix + randomString(),
			},
		}

		scheme := setupScheme()
		initObjects := []client.Object{accessRequest}
		c = fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initObjects...).
			WithObjects(initObjects...).Build()
	})

	It("Return nil,error if AccessRequest is not specified", func() {
		params := scope.AccessRequestScopeParams{
			Client: c,
			Logger: logger,
		}

		scope, err := scope.NewAccessRequestScope(params)
		Expect(err).To(HaveOccurred())
		Expect(scope).To(BeNil())
	})

	It("Return nil,error if client is not specified", func() {
		params := scope.AccessRequestScopeParams{
			AccessRequest: accessRequest,
			Logger:        logger,
		}

		scope, err := scope.NewAccessRequestScope(params)
		Expect(err).To(HaveOccurred())
		Expect(scope).To(BeNil())
	})

	It("Name returns AccessRequest Name", func() {
		params := scope.AccessRequestScopeParams{
			Client:        c,
			AccessRequest: accessRequest,
			Logger:        logger,
		}

		scope, err := scope.NewAccessRequestScope(params)
		Expect(err).ToNot(HaveOccurred())
		Expect(scope).ToNot(BeNil())

		Expect(scope.Name()).To(Equal(accessRequest.Name))
	})

	It("SetSecretRef updates AccessRequest Status SecretRef", func() {
		params := scope.AccessRequestScopeParams{
			Client:        c,
			AccessRequest: accessRequest,
			Logger:        logger,
		}

		scope, err := scope.NewAccessRequestScope(params)
		Expect(err).ToNot(HaveOccurred())
		Expect(scope).ToNot(BeNil())

		secretNamespace := randomString()
		secretName := randomString()

		secretRef := corev1.ObjectReference{Namespace: secretNamespace, Name: secretName}

		scope.SetSecretRef(&secretRef)
		Expect(accessRequest.Status.SecretRef).ToNot(BeNil())
		Expect(accessRequest.Status.SecretRef.Namespace).To(Equal(secretNamespace))
		Expect(accessRequest.Status.SecretRef.Name).To(Equal(secretName))
	})

	It("SetFailureMessage sets RoleRequest.Status.FailureMessage", func() {
		params := scope.AccessRequestScopeParams{
			Client:        c,
			AccessRequest: accessRequest,
			Logger:        logger,
		}

		scope, err := scope.NewAccessRequestScope(params)
		Expect(err).ToNot(HaveOccurred())
		Expect(scope).ToNot(BeNil())

		failureMessage := randomString()
		scope.SetFailureMessage(&failureMessage)
		Expect(accessRequest.Status.FailureMessage).ToNot(BeNil())
		Expect(*accessRequest.Status.FailureMessage).To(Equal(failureMessage))
	})
})
