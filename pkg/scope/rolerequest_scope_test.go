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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/klogr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectsveltos/access-manager/pkg/scope"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
)

var _ = Describe("RoleRequestScope", func() {
	var roleRequest *libsveltosv1alpha1.RoleRequest
	var c client.Client

	BeforeEach(func() {
		roleRequest = &libsveltosv1alpha1.RoleRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: classifierNamePrefix + randomString(),
			},
		}

		scheme := setupScheme()
		initObjects := []client.Object{roleRequest}
		c = fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initObjects...).
			WithObjects(initObjects...).Build()
	})

	It("Return nil,error if RoleRequest is not specified", func() {
		params := scope.RoleRequestScopeParams{
			Client: c,
			Logger: klogr.New(),
		}

		scope, err := scope.NewRoleRequestScope(params)
		Expect(err).To(HaveOccurred())
		Expect(scope).To(BeNil())
	})

	It("Return nil,error if client is not specified", func() {
		params := scope.RoleRequestScopeParams{
			RoleRequest: roleRequest,
			Logger:      klogr.New(),
		}

		scope, err := scope.NewRoleRequestScope(params)
		Expect(err).To(HaveOccurred())
		Expect(scope).To(BeNil())
	})

	It("Name returns RoleRequest Name", func() {
		params := scope.RoleRequestScopeParams{
			Client:      c,
			RoleRequest: roleRequest,
			Logger:      klogr.New(),
		}

		scope, err := scope.NewRoleRequestScope(params)
		Expect(err).ToNot(HaveOccurred())
		Expect(scope).ToNot(BeNil())

		Expect(scope.Name()).To(Equal(roleRequest.Name))
	})

	It("SetMatchingClusterRefs updates MatchingClusterRefs Status field", func() {
		params := scope.RoleRequestScopeParams{
			Client:      c,
			RoleRequest: roleRequest,
			Logger:      klogr.New(),
		}

		scope, err := scope.NewRoleRequestScope(params)
		Expect(err).ToNot(HaveOccurred())
		Expect(scope).ToNot(BeNil())

		matchingClusterRefs := []corev1.ObjectReference{
			{
				Kind:      "Cluster",
				Namespace: randomString(),
				Name:      randomString(),
			},
		}

		scope.SetMatchingClusterRefs(matchingClusterRefs)
		Expect(roleRequest.Status.MatchingClusterRefs).ToNot(BeNil())
		Expect(roleRequest.Status.MatchingClusterRefs).To(ContainElement(matchingClusterRefs[0]))
	})

	It("SetClusterInfo updates RoleRequest Status ClusterInfo", func() {
		params := scope.RoleRequestScopeParams{
			Client:      c,
			RoleRequest: roleRequest,
			Logger:      klogr.New(),
		}

		scope, err := scope.NewRoleRequestScope(params)
		Expect(err).ToNot(HaveOccurred())
		Expect(scope).ToNot(BeNil())

		clusterNamespace := randomString()
		clusterName := randomString()
		hash := []byte(randomString())
		clusterInfo := libsveltosv1alpha1.ClusterInfo{
			Cluster: corev1.ObjectReference{Namespace: clusterNamespace, Name: clusterName},
			Status:  libsveltosv1alpha1.SveltosStatusProvisioned,
			Hash:    hash,
		}
		scope.SetClusterInfo([]libsveltosv1alpha1.ClusterInfo{clusterInfo})
		Expect(roleRequest.Status.ClusterInfo).ToNot(BeNil())
		Expect(len(roleRequest.Status.ClusterInfo)).To(Equal(1))
		Expect(roleRequest.Status.ClusterInfo[0].Cluster.Namespace).To(Equal(clusterNamespace))
		Expect(roleRequest.Status.ClusterInfo[0].Cluster.Name).To(Equal(clusterName))
		Expect(roleRequest.Status.ClusterInfo[0].Hash).To(Equal(hash))
		Expect(roleRequest.Status.ClusterInfo[0].Status).To(Equal(libsveltosv1alpha1.SveltosStatusProvisioned))
	})

	It("SetFailureMessage sets RoleRequest.Status.FailureMessage", func() {
		params := scope.RoleRequestScopeParams{
			Client:      c,
			RoleRequest: roleRequest,
			Logger:      klogr.New(),
		}

		scope, err := scope.NewRoleRequestScope(params)
		Expect(err).ToNot(HaveOccurred())
		Expect(scope).ToNot(BeNil())

		failureMessage := randomString()
		scope.SetFailureMessage(&failureMessage)
		Expect(roleRequest.Status.FailureMessage).ToNot(BeNil())
		Expect(*roleRequest.Status.FailureMessage).To(Equal(failureMessage))
	})
})
