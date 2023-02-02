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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/klogr"

	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/projectsveltos/access-manager/controllers"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	fakedeployer "github.com/projectsveltos/libsveltos/lib/deployer/fake"
)

var _ = Describe("RoleRequets: Reconciler", func() {
	var roleRequest *libsveltosv1alpha1.RoleRequest

	BeforeEach(func() {
		roleRequest = getRoleRequest(nil, nil, randomString())
	})

	It("Adds finalizer", func() {
		initObjects := []client.Object{
			roleRequest,
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initObjects...).Build()

		reconciler := getRoleRequestReconciler(c, nil)

		roleRequestName := client.ObjectKey{
			Name: roleRequest.Name,
		}
		_, err := reconciler.Reconcile(context.TODO(), ctrl.Request{
			NamespacedName: roleRequestName,
		})
		Expect(err).ToNot(HaveOccurred())

		currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}
		err = c.Get(context.TODO(), roleRequestName, currentRoleRequest)
		Expect(err).ToNot(HaveOccurred())
		Expect(
			controllerutil.ContainsFinalizer(
				currentRoleRequest,
				libsveltosv1alpha1.RoleRequestFinalizer,
			),
		).Should(BeTrue())
	})

	It("Remove finalizer", func() {
		Expect(controllerutil.AddFinalizer(roleRequest, libsveltosv1alpha1.RoleRequestFinalizer)).To(BeTrue())

		cluster := &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}

		Expect(addTypeInformationToObject(scheme, cluster)).To(Succeed())

		initObjects := []client.Object{
			roleRequest,
			cluster,
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initObjects...).Build()

		roleRequestName := client.ObjectKey{
			Name: roleRequest.Name,
		}

		currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}

		Expect(c.Get(context.TODO(), roleRequestName, currentRoleRequest)).To(Succeed())
		currentRoleRequest.Status.ClusterInfo = []libsveltosv1alpha1.ClusterInfo{
			{
				Cluster: corev1.ObjectReference{
					Namespace:  cluster.Namespace,
					Name:       cluster.Name,
					APIVersion: cluster.APIVersion,
					Kind:       cluster.Kind,
				},
				Status: libsveltosv1alpha1.SveltosStatusProvisioned,
				Hash:   []byte(randomString()),
			},
		}

		Expect(c.Status().Update(context.TODO(), currentRoleRequest)).To(Succeed())

		Expect(c.Get(context.TODO(), roleRequestName, currentRoleRequest)).To(Succeed())
		Expect(c.Delete(context.TODO(), currentRoleRequest)).To(Succeed())

		dep := fakedeployer.GetClient(context.TODO(), klogr.New(), testEnv.Client)
		Expect(dep.RegisterFeatureID(libsveltosv1alpha1.FeatureRoleRequest)).To(Succeed())

		reconciler := getRoleRequestReconciler(c, dep)

		// Because RoleRequest is currently deployed in a Cluster (Status.ClusterInfo is set
		// indicating that) Reconcile won't be removed Finalizer
		_, err := reconciler.Reconcile(context.TODO(), ctrl.Request{
			NamespacedName: roleRequestName,
		})
		Expect(err).ToNot(HaveOccurred())

		err = c.Get(context.TODO(), roleRequestName, currentRoleRequest)
		Expect(err).ToNot(HaveOccurred())
		Expect(controllerutil.ContainsFinalizer(currentRoleRequest, libsveltosv1alpha1.RoleRequestFinalizer)).To(BeTrue())

		currentRoleRequest.Status.ClusterInfo = []libsveltosv1alpha1.ClusterInfo{}
		Expect(c.Status().Update(context.TODO(), currentRoleRequest)).To(Succeed())

		// Because RoleRequest is currently deployed nowhere (Status.ClusterInfo is set
		// indicating that) Reconcile will be removed Finalizer
		_, err = reconciler.Reconcile(context.TODO(), ctrl.Request{
			NamespacedName: roleRequestName,
		})
		Expect(err).ToNot(HaveOccurred())

		err = c.Get(context.TODO(), roleRequestName, currentRoleRequest)
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("getMatchingClusters finds all matching clusters", func() {
		sveltosCluster := &libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      randomString(),
				Namespace: randomString(),
				Labels: map[string]string{
					"env":  "qa",
					"zone": "west",
				},
			},
		}

		matchingCluster := &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      randomString(),
				Namespace: randomString(),
				Labels: map[string]string{
					"env":  "qa",
					"zone": "west",
				},
			},
		}

		nonMatchingCluster := &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      randomString(),
				Namespace: randomString(),
				Labels: map[string]string{
					"zone": "west",
				},
			},
		}

		roleRequest := getRoleRequest(nil, nil, randomString())
		roleRequest.Spec.ClusterSelector = libsveltosv1alpha1.Selector("env=qa,zone=west")

		initObjects := []client.Object{
			roleRequest,
			matchingCluster,
			sveltosCluster,
			nonMatchingCluster,
		}

		Expect(addTypeInformationToObject(scheme, matchingCluster))
		Expect(addTypeInformationToObject(scheme, sveltosCluster))

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initObjects...).Build()

		reconciler := getRoleRequestReconciler(c, nil)

		roleRequestScope := getRoleRequestScope(c, klogr.New(), roleRequest)

		matches, err := controllers.GetMatchingClusters(reconciler, context.TODO(), roleRequestScope)
		Expect(err).To(BeNil())
		Expect(len(matches)).To(Equal(2))
		Expect(matches).To(ContainElement(
			corev1.ObjectReference{Namespace: matchingCluster.Namespace, Name: matchingCluster.Name,
				Kind: matchingCluster.Kind, APIVersion: matchingCluster.APIVersion}))
		Expect(matches).To(ContainElement(
			corev1.ObjectReference{Namespace: sveltosCluster.Namespace, Name: sveltosCluster.Name,
				Kind: sveltosCluster.Kind, APIVersion: sveltosCluster.APIVersion}))
	})
})
