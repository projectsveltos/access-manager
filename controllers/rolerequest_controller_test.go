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

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2/textlogger"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta1" //nolint:staticcheck // SA1019: We are unable to update the dependency at this time.
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/projectsveltos/access-manager/controllers"
	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
	fakedeployer "github.com/projectsveltos/libsveltos/lib/deployer/fake"
)

var _ = Describe("RoleRequets: Reconciler", func() {
	var roleRequest *libsveltosv1beta1.RoleRequest
	var logger logr.Logger

	BeforeEach(func() {
		logger = textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1)))
		roleRequest = getRoleRequest(nil, nil, randomString(), randomString())
	})

	It("Adds finalizer", func() {
		initObjects := []client.Object{
			roleRequest,
		}

		c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initObjects...).
			WithObjects(initObjects...).Build()

		reconciler := getRoleRequestReconciler(c, nil)

		roleRequestName := client.ObjectKey{
			Name: roleRequest.Name,
		}
		_, err := reconciler.Reconcile(context.TODO(), ctrl.Request{
			NamespacedName: roleRequestName,
		})
		Expect(err).ToNot(HaveOccurred())

		currentRoleRequest := &libsveltosv1beta1.RoleRequest{}
		err = c.Get(context.TODO(), roleRequestName, currentRoleRequest)
		Expect(err).ToNot(HaveOccurred())
		Expect(
			controllerutil.ContainsFinalizer(
				currentRoleRequest,
				libsveltosv1beta1.RoleRequestFinalizer,
			),
		).Should(BeTrue())
	})

	It("Remove finalizer", func() {
		Expect(controllerutil.AddFinalizer(roleRequest, libsveltosv1beta1.RoleRequestFinalizer)).To(BeTrue())

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

		c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initObjects...).
			WithObjects(initObjects...).Build()

		roleRequestName := client.ObjectKey{
			Name: roleRequest.Name,
		}

		currentRoleRequest := &libsveltosv1beta1.RoleRequest{}

		Expect(c.Get(context.TODO(), roleRequestName, currentRoleRequest)).To(Succeed())
		currentRoleRequest.Status.ClusterInfo = []libsveltosv1beta1.ClusterInfo{
			{
				Cluster: corev1.ObjectReference{
					Namespace:  cluster.Namespace,
					Name:       cluster.Name,
					APIVersion: cluster.APIVersion,
					Kind:       cluster.Kind,
				},
				Status: libsveltosv1beta1.SveltosStatusProvisioned,
				Hash:   []byte(randomString()),
			},
		}

		Expect(c.Status().Update(context.TODO(), currentRoleRequest)).To(Succeed())

		Expect(c.Get(context.TODO(), roleRequestName, currentRoleRequest)).To(Succeed())
		Expect(c.Delete(context.TODO(), currentRoleRequest)).To(Succeed())

		dep := fakedeployer.GetClient(context.TODO(), logger, testEnv.Client)
		Expect(dep.RegisterFeatureID(libsveltosv1beta1.FeatureRoleRequest)).To(Succeed())

		reconciler := getRoleRequestReconciler(c, dep)

		// Because RoleRequest is currently deployed in a Cluster (Status.ClusterInfo is set
		// indicating that) Reconcile won't be removed Finalizer
		_, err := reconciler.Reconcile(context.TODO(), ctrl.Request{
			NamespacedName: roleRequestName,
		})
		Expect(err).ToNot(HaveOccurred())

		err = c.Get(context.TODO(), roleRequestName, currentRoleRequest)
		Expect(err).ToNot(HaveOccurred())
		Expect(controllerutil.ContainsFinalizer(currentRoleRequest, libsveltosv1beta1.RoleRequestFinalizer)).To(BeTrue())

		currentRoleRequest.Status.ClusterInfo = []libsveltosv1beta1.ClusterInfo{}
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
		sveltosCluster := &libsveltosv1beta1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      randomString(),
				Namespace: randomString(),
				Labels: map[string]string{
					"env":  "qa",
					"zone": "west",
				},
			},
			Status: libsveltosv1beta1.SveltosClusterStatus{
				Ready: true,
			},
		}

		initialized := true
		matchingCluster := &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      randomString(),
				Namespace: randomString(),
				Labels: map[string]string{
					"env":  "qa",
					"zone": "west",
				},
			},
			Status: clusterv1.ClusterStatus{
				ControlPlaneReady: initialized,
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
			Status: clusterv1.ClusterStatus{
				ControlPlaneReady: initialized,
			},
		}

		roleRequest.Spec.ClusterSelector = libsveltosv1beta1.Selector{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"env":  "qa",
					"zone": "west",
				},
			},
		}

		clusterCRD := generateTestClusterAPICRD("cluster", "clusters")

		initObjects := []client.Object{
			clusterCRD,
			roleRequest,
			matchingCluster,
			sveltosCluster,
			nonMatchingCluster,
		}

		Expect(addTypeInformationToObject(scheme, matchingCluster))
		Expect(addTypeInformationToObject(scheme, sveltosCluster))

		c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initObjects...).
			WithObjects(initObjects...).Build()

		reconciler := getRoleRequestReconciler(c, nil)

		roleRequestScope := getRoleRequestScope(c, logger, roleRequest)

		matches, err := controllers.GetMatchingClusters(reconciler, context.TODO(), roleRequestScope, logger)
		Expect(err).To(BeNil())
		Expect(len(matches)).To(Equal(2))
		Expect(matches).To(ContainElement(
			corev1.ObjectReference{Namespace: matchingCluster.Namespace, Name: matchingCluster.Name,
				Kind: matchingCluster.Kind, APIVersion: matchingCluster.APIVersion}))
		Expect(matches).To(ContainElement(
			corev1.ObjectReference{Namespace: sveltosCluster.Namespace, Name: sveltosCluster.Name,
				Kind: sveltosCluster.Kind, APIVersion: sveltosCluster.APIVersion}))
	})

	It("getClosestExpirationTime returns the interval to next TokenRequest expiration time", func() {
		roleRequest := getRoleRequest(nil, nil, randomString(), randomString())
		Expect(testEnv.Create(context.TODO(), roleRequest)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, roleRequest)
		Expect(addTypeInformationToObject(scheme, roleRequest)).To(Succeed())

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: roleRequest.Spec.ServiceAccountNamespace,
			},
		}
		Expect(testEnv.Create(context.TODO(), ns)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, ns)

		serviceAccount := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: roleRequest.Spec.ServiceAccountNamespace,
				Name:      roleRequest.Spec.ServiceAccountName,
			},
		}
		Expect(testEnv.Create(context.TODO(), serviceAccount)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, serviceAccount)

		type clusterInfo struct {
			namespace string
			name      string
		}

		clusters := []clusterInfo{
			{randomString(), randomString()},
			{randomString(), randomString()},
			{randomString(), randomString()},
		}

		aDay := int64(24 * 60 * 60)
		for i := range clusters {
			// Create cluster namespace
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusters[i].namespace,
				},
			}
			Expect(testEnv.Create(context.TODO(), ns)).To(Succeed())
			waitForObject(context.TODO(), testEnv.Client, ns)

			expiration := int64(i+1) * (aDay) // multiple of a day
			treq := &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					ExpirationSeconds: &expiration,
				},
			}
			clientset, err := kubernetes.NewForConfig(testEnv.Config)
			Expect(err).To(BeNil())

			// Create a TokenRequest with expiration time set in a day
			var tokenRequest *authenticationv1.TokenRequest
			tokenRequest, err = clientset.CoreV1().ServiceAccounts(roleRequest.Spec.ServiceAccountNamespace).
				CreateToken(ctx, roleRequest.Spec.ServiceAccountName, treq, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			// CreateSecretWithKubeconfig creates the Secret and stores there both Kubeconfig (test is
			// passing random value for kubeconfig) and the tokenRequest expiration time.
			// Owner of those secrets is the roleRequest.
			Expect(controllers.CreateSecretWithKubeconfig(context.TODO(), testEnv.Client, roleRequest,
				clusters[i].namespace, clusters[i].name, libsveltosv1beta1.ClusterTypeSveltos,
				[]byte(randomString()), &tokenRequest.Status, logger)).To(Succeed())

			// Wait for cache to sync
			Eventually(func() error {
				_, err := controllers.GetSecretWithKubeconfig(context.TODO(),
					testEnv.Client, roleRequest, clusters[i].namespace,
					clusters[i].name, libsveltosv1beta1.ClusterTypeSveltos, logger)
				return err
			}, timeout, pollingInterval).Should(BeNil())
		}

		// Test is pretending this roleRequest was deployed in 3 different clusters.
		// Token expiration time is set to one day for a cluster, two days for a second cluster
		// and three days for the third cluster
		roleRequestScope := getRoleRequestScope(testEnv.Client, logger, roleRequest)
		roleRequestReconciler := getRoleRequestReconciler(testEnv.Client, nil)
		nextReconciliationTime, err := controllers.GetClosestExpirationTime(roleRequestReconciler,
			context.TODO(), roleRequestScope, logger)
		Expect(err).To(BeNil())
		Expect(nextReconciliationTime).ToNot(BeNil())
		// Verify that nextReconciliationTime is less than a day and within 10 seconds from a day
		// as few seconds have elapsed since when test generated first TokenRequest
		Expect(nextReconciliationTime.Seconds()).To(BeNumerically("<", aDay))
		Expect(nextReconciliationTime.Seconds()).To(BeNumerically(">", aDay-10))
	})
})
