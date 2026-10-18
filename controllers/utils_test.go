/*
Copyright 2026. projectsveltos.io. All rights reserved.

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

package controllers_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"

	"github.com/projectsveltos/access-manager/controllers"
	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
)

var _ = Describe("Utils", func() {
	It("InitScheme registers RoleRequest", func() {
		scheme, err := controllers.InitScheme()
		Expect(err).To(BeNil())

		gvks, _, err := scheme.ObjectKinds(&libsveltosv1beta1.RoleRequest{})
		Expect(err).To(BeNil())
		Expect(gvks).ToNot(BeEmpty())
		Expect(gvks[0].Kind).To(Equal(libsveltosv1beta1.RoleRequestKind))
	})

	It("InitScheme registers rbac Role and ClusterRole", func() {
		scheme, err := controllers.InitScheme()
		Expect(err).To(BeNil())

		_, _, err = scheme.ObjectKinds(&rbacv1.Role{})
		Expect(err).To(BeNil())

		_, _, err = scheme.ObjectKinds(&rbacv1.ClusterRole{})
		Expect(err).To(BeNil())
	})

	It("InitScheme registers cluster-api Cluster and CustomResourceDefinition", func() {
		scheme, err := controllers.InitScheme()
		Expect(err).To(BeNil())

		_, _, err = scheme.ObjectKinds(&clusterv1.Cluster{})
		Expect(err).To(BeNil())

		_, _, err = scheme.ObjectKinds(&apiextensionsv1.CustomResourceDefinition{})
		Expect(err).To(BeNil())
	})

	It("getKeyFromObject returns namespace, name, kind and apiVersion for a RoleRequest", func() {
		scheme, err := controllers.InitScheme()
		Expect(err).To(BeNil())

		roleRequest := &libsveltosv1beta1.RoleRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "my-role-request"},
		}

		key := controllers.GetKeyFromObject(scheme, roleRequest)
		Expect(key.Name).To(Equal("my-role-request"))
		Expect(key.Kind).To(Equal(libsveltosv1beta1.RoleRequestKind))
		Expect(key.APIVersion).To(ContainSubstring(libsveltosv1beta1.GroupVersion.String()))
	})

	It("getKeyFromObject returns namespace and name for a namespaced ConfigMap", func() {
		scheme, err := controllers.InitScheme()
		Expect(err).To(BeNil())

		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-cm"},
		}

		key := controllers.GetKeyFromObject(scheme, configMap)
		Expect(key.Namespace).To(Equal("ns"))
		Expect(key.Name).To(Equal("my-cm"))
		Expect(key.Kind).To(Equal("ConfigMap"))
	})

	It("getKeyFromObject panics for an object type not registered in the scheme", func() {
		scheme, err := controllers.InitScheme()
		Expect(err).To(BeNil())

		type unregistered struct {
			corev1.ConfigMap
		}

		Expect(func() {
			controllers.GetKeyFromObject(scheme, &unregistered{})
		}).To(Panic())
	})
})
