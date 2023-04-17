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

package controllers_test

import (
	"context"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/projectsveltos/access-manager/controllers"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	libsveltosset "github.com/projectsveltos/libsveltos/lib/set"
)

var _ = Describe("ClustersummaryTransformations map functions", func() {
	It("RequeueClusterSummaryForReference returns matching ClusterSummary", func() {
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      randomString(),
				Namespace: randomString(),
			},
		}

		Expect(addTypeInformationToObject(scheme, configMap)).To(Succeed())

		roleRequest0 := &libsveltosv1alpha1.RoleRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: randomString(),
			},
			Spec: libsveltosv1alpha1.RoleRequestSpec{
				RoleRefs: []libsveltosv1alpha1.PolicyRef{
					{
						Namespace: configMap.Namespace,
						Name:      configMap.Name,
						Kind:      string(libsveltosv1alpha1.ConfigMapReferencedResourceKind),
					},
				},
			},
		}

		roleRequest1 := &libsveltosv1alpha1.RoleRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: randomString(),
			},
			Spec: libsveltosv1alpha1.RoleRequestSpec{
				RoleRefs: []libsveltosv1alpha1.PolicyRef{
					{
						Namespace: configMap.Namespace,
						Name:      randomString(),
						Kind:      string(libsveltosv1alpha1.ConfigMapReferencedResourceKind),
					},
				},
			},
		}

		initObjects := []client.Object{
			configMap,
			roleRequest0,
			roleRequest1,
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initObjects...).Build()

		reconciler := &controllers.RoleRequestReconciler{
			Client:                  c,
			Scheme:                  scheme,
			RoleRequests:            make(map[corev1.ObjectReference]libsveltosv1alpha1.Selector),
			ClusterMap:              make(map[corev1.ObjectReference]*libsveltosset.Set),
			RoleRequestClusterMap:   make(map[corev1.ObjectReference]*libsveltosset.Set),
			ReferenceMap:            make(map[corev1.ObjectReference]*libsveltosset.Set),
			RoleRequestReferenceMap: make(map[corev1.ObjectReference]*libsveltosset.Set),
			Mux:                     sync.Mutex{},
		}

		key := corev1.ObjectReference{APIVersion: configMap.APIVersion,
			Kind: string(libsveltosv1alpha1.ConfigMapReferencedResourceKind), Namespace: configMap.Namespace, Name: configMap.Name}

		set := libsveltosset.Set{}
		set.Insert(&corev1.ObjectReference{APIVersion: libsveltosv1alpha1.GroupVersion.String(),
			Kind: libsveltosv1alpha1.RoleRequestKind, Name: roleRequest0.Name})
		reconciler.ReferenceMap[key] = &set

		requests := controllers.RequeueRoleRequestForReference(reconciler, configMap)
		Expect(requests).To(HaveLen(1))
		Expect(requests[0].Name).To(Equal(roleRequest0.Name))

		set.Insert(&corev1.ObjectReference{APIVersion: libsveltosv1alpha1.GroupVersion.String(),
			Kind: libsveltosv1alpha1.RoleRequestKind, Name: roleRequest1.Name})
		reconciler.ReferenceMap[key] = &set

		requests = controllers.RequeueRoleRequestForReference(reconciler, configMap)
		Expect(requests).To(HaveLen(2))
		Expect(requests).To(ContainElement(reconcile.Request{NamespacedName: types.NamespacedName{Name: roleRequest0.Name}}))
		Expect(requests).To(ContainElement(reconcile.Request{NamespacedName: types.NamespacedName{Name: roleRequest1.Name}}))
	})

	It("requeueRoleRequestForCluster returns matching RoleRequests", func() {
		namespace := randomString()
		cluster := &libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      randomString(),
				Namespace: namespace,
				Labels: map[string]string{
					"env": "production",
				},
			},
		}

		matchingRoleRequest := &libsveltosv1alpha1.RoleRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: randomString(),
			},
			Spec: libsveltosv1alpha1.RoleRequestSpec{
				ClusterSelector:         libsveltosv1alpha1.Selector("env=production"),
				ServiceAccountName:      randomString(),
				ServiceAccountNamespace: randomString(),
			},
		}

		nonMatchingRoleRequest := &libsveltosv1alpha1.RoleRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: randomString(),
			},
			Spec: libsveltosv1alpha1.RoleRequestSpec{
				ClusterSelector:         libsveltosv1alpha1.Selector("env=qa"),
				ServiceAccountName:      randomString(),
				ServiceAccountNamespace: randomString(),
			},
		}

		initObjects := []client.Object{
			matchingRoleRequest,
			nonMatchingRoleRequest,
			cluster,
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initObjects...).Build()

		reconciler := &controllers.RoleRequestReconciler{
			Client:                  c,
			Scheme:                  scheme,
			RoleRequests:            make(map[corev1.ObjectReference]libsveltosv1alpha1.Selector),
			ClusterMap:              make(map[corev1.ObjectReference]*libsveltosset.Set),
			RoleRequestClusterMap:   make(map[corev1.ObjectReference]*libsveltosset.Set),
			ReferenceMap:            make(map[corev1.ObjectReference]*libsveltosset.Set),
			RoleRequestReferenceMap: make(map[corev1.ObjectReference]*libsveltosset.Set),
			Mux:                     sync.Mutex{},
		}

		By("Setting RoleRequestReconciler internal structures")
		matchingInfo := corev1.ObjectReference{APIVersion: cluster.APIVersion,
			Kind: libsveltosv1alpha1.SveltosClusterKind, Name: matchingRoleRequest.Name}
		reconciler.RoleRequests[matchingInfo] = matchingRoleRequest.Spec.ClusterSelector
		nonMatchingInfo := corev1.ObjectReference{APIVersion: cluster.APIVersion,
			Kind: libsveltosv1alpha1.SveltosClusterKind, Name: nonMatchingRoleRequest.Name}
		reconciler.RoleRequests[nonMatchingInfo] = nonMatchingRoleRequest.Spec.ClusterSelector

		// ClusterMap contains, per ClusterName, list of RoleRequest matching it.
		clusterProfileSet := &libsveltosset.Set{}
		clusterProfileSet.Insert(&matchingInfo)
		clusterInfo := corev1.ObjectReference{APIVersion: cluster.APIVersion, Kind: cluster.Kind, Namespace: cluster.Namespace, Name: cluster.Name}
		reconciler.ClusterMap[clusterInfo] = clusterProfileSet

		// RoleRequestClusterMap contains, per RoleRequest, list of matched Clusters.
		clusterSet1 := &libsveltosset.Set{}
		reconciler.RoleRequestClusterMap[nonMatchingInfo] = clusterSet1

		clusterSet2 := &libsveltosset.Set{}
		clusterSet2.Insert(&clusterInfo)
		reconciler.RoleRequestClusterMap[matchingInfo] = clusterSet2

		By("Expect only matchingRoleRequest to be requeued")
		requests := controllers.RequeueRoleRequestForCluster(reconciler, cluster)
		expected := reconcile.Request{NamespacedName: types.NamespacedName{Name: matchingRoleRequest.Name}}
		Expect(requests).To(ContainElement(expected))

		By("Changing roleRequest ClusterSelector again to have two ClusterProfiles match")
		nonMatchingRoleRequest.Spec.ClusterSelector = matchingRoleRequest.Spec.ClusterSelector
		Expect(c.Update(context.TODO(), nonMatchingRoleRequest)).To(Succeed())

		reconciler.RoleRequests[nonMatchingInfo] = nonMatchingRoleRequest.Spec.ClusterSelector

		clusterSet1.Insert(&clusterInfo)
		reconciler.RoleRequestClusterMap[nonMatchingInfo] = clusterSet1

		clusterProfileSet.Insert(&nonMatchingInfo)
		reconciler.ClusterMap[clusterInfo] = clusterProfileSet

		requests = controllers.RequeueRoleRequestForCluster(reconciler, cluster)
		expected = reconcile.Request{NamespacedName: types.NamespacedName{Name: matchingRoleRequest.Name}}
		Expect(requests).To(ContainElement(expected))
		expected = reconcile.Request{NamespacedName: types.NamespacedName{Name: nonMatchingRoleRequest.Name}}
		Expect(requests).To(ContainElement(expected))

		By("Changing roleRequest ClusterSelector again to have no ClusterProfile match")
		matchingRoleRequest.Spec.ClusterSelector = libsveltosv1alpha1.Selector("env=qa")
		Expect(c.Update(context.TODO(), matchingRoleRequest)).To(Succeed())
		nonMatchingRoleRequest.Spec.ClusterSelector = matchingRoleRequest.Spec.ClusterSelector
		Expect(c.Update(context.TODO(), nonMatchingRoleRequest)).To(Succeed())

		emptySet := &libsveltosset.Set{}
		reconciler.RoleRequestClusterMap[matchingInfo] = emptySet
		reconciler.RoleRequestClusterMap[nonMatchingInfo] = emptySet
		reconciler.ClusterMap[clusterInfo] = emptySet

		reconciler.RoleRequests[matchingInfo] = matchingRoleRequest.Spec.ClusterSelector
		reconciler.RoleRequests[nonMatchingInfo] = nonMatchingRoleRequest.Spec.ClusterSelector

		requests = controllers.RequeueRoleRequestForCluster(reconciler, cluster)
		Expect(requests).To(HaveLen(0))
	})
})
