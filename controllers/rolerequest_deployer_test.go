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
	"crypto/sha256"
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gdexlab/go-render/render"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2/klogr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectsveltos/access-manager/controllers"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	"github.com/projectsveltos/libsveltos/lib/deployer"
	fakedeployer "github.com/projectsveltos/libsveltos/lib/deployer/fake"
	"github.com/projectsveltos/libsveltos/lib/roles"
	"github.com/projectsveltos/libsveltos/lib/utils"
)

var _ = Describe("Deployer", func() {
	It("roleRequestHash returns roleRequest hash", func() {
		referecedResourceNamespace := randomString()

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: referecedResourceNamespace,
			},
		}

		Expect(testEnv.Create(context.TODO(), ns)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, ns)

		viewClusterRoleName := randomString()
		configMap := createConfigMapWithPolicy(referecedResourceNamespace, randomString(),
			fmt.Sprintf(viewClusterRole, viewClusterRoleName))

		Expect(testEnv.Create(context.TODO(), configMap)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, configMap)
		Expect(addTypeInformationToObject(scheme, configMap)).To(Succeed())

		modifyClusterRoleName := randomString()
		secret := createSecretWithPolicy(referecedResourceNamespace, randomString(),
			fmt.Sprintf(modifyClusterRole, modifyClusterRoleName))

		Expect(testEnv.Create(context.TODO(), secret)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, secret)
		Expect(addTypeInformationToObject(scheme, secret)).To(Succeed())

		roleRequest := getRoleRequest([]corev1.ConfigMap{*configMap}, []corev1.Secret{*secret},
			randomString(), randomString())
		Expect(testEnv.Create(context.TODO(), roleRequest)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, roleRequest)

		h := sha256.New()
		var config string
		config += render.AsCode(roleRequest.Spec)
		config += render.AsCode(configMap)
		config += render.AsCode(secret)
		h.Write([]byte(config))
		hash := h.Sum(nil)

		currentHash, err := controllers.RoleRequestHash(ctx, testEnv.Client, randomString(),
			roleRequest, klogr.New())
		Expect(err).To(BeNil())
		Expect(reflect.DeepEqual(currentHash, hash)).To(BeTrue())
	})

	It("deployRoleRequestInCluster deploys resources in referenced ConfigMaps/Secrets", func() {
		sveltosCluster := libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}

		prepareForTesting(&sveltosCluster)

		referecedResourceNamespace := randomString()

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: referecedResourceNamespace,
			},
		}

		Expect(testEnv.Create(context.TODO(), ns)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, ns)

		viewClusterRoleName := randomString()
		configMap := createConfigMapWithPolicy(referecedResourceNamespace, randomString(),
			fmt.Sprintf(viewClusterRole, viewClusterRoleName))

		Expect(testEnv.Create(context.TODO(), configMap)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, configMap)
		Expect(addTypeInformationToObject(scheme, configMap)).To(Succeed())

		modifyClusterRoleName := randomString()
		secret := createSecretWithPolicy(referecedResourceNamespace, randomString(),
			fmt.Sprintf(modifyClusterRole, modifyClusterRoleName))

		Expect(testEnv.Create(context.TODO(), secret)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, secret)
		Expect(addTypeInformationToObject(scheme, secret)).To(Succeed())

		roleRequest := getRoleRequest([]corev1.ConfigMap{*configMap}, []corev1.Secret{*secret},
			randomString(), randomString())
		Expect(testEnv.Create(context.TODO(), roleRequest)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, roleRequest)

		Expect(controllers.DeployRoleRequestInCluster(context.TODO(), testEnv.Client,
			sveltosCluster.Namespace, sveltosCluster.Name, roleRequest.Name, libsveltosv1alpha1.FeatureRoleRequest,
			libsveltosv1alpha1.ClusterTypeSveltos, deployer.Options{}, klogr.New())).To(Succeed())

		// Verify all ClusterRoles are present
		Eventually(func() bool {
			currentClusterRole := &rbacv1.ClusterRole{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Name: viewClusterRoleName},
				currentClusterRole)
			if err != nil {
				return false
			}
			return validateLabels(currentClusterRole, configMap)
		}, timeout, pollingInterval).Should(BeTrue())

		Eventually(func() bool {
			currentClusterRole := &rbacv1.ClusterRole{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Name: modifyClusterRoleName},
				currentClusterRole)
			if err != nil {
				return false
			}
			return validateLabels(currentClusterRole, secret)
		}, timeout, pollingInterval).Should(BeTrue())

		// Name of the ServiceAccount created by Sveltos in the managed cluster
		saName := roles.GetServiceAccountNameInManagedCluster(
			roleRequest.Spec.ServiceAccountNamespace, roleRequest.Spec.ServiceAccountName)

		// Verify ClusterRoleBinding are present
		currentClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Name: viewClusterRoleName},
			currentClusterRoleBinding)).To(Succeed())
		Expect(currentClusterRoleBinding.Subjects).ToNot(BeNil())
		Expect(len(currentClusterRoleBinding.Subjects)).To(Equal(1))
		Expect(currentClusterRoleBinding.Subjects[0].Name).To(Equal(saName))
		Expect(currentClusterRoleBinding.Subjects[0].Namespace).To(Equal(controllers.ServiceAccountNamespace))

		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Name: modifyClusterRoleName},
			currentClusterRoleBinding)).To(Succeed())
		Expect(currentClusterRoleBinding.Subjects).ToNot(BeNil())
		Expect(len(currentClusterRoleBinding.Subjects)).To(Equal(1))
		Expect(currentClusterRoleBinding.Subjects[0].Name).To(Equal(saName))
		Expect(currentClusterRoleBinding.Subjects[0].Namespace).To(Equal(controllers.ServiceAccountNamespace))

		// Verify ServiceAccount is present
		currentServiceAccount := &corev1.ServiceAccount{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Namespace: controllers.ServiceAccountNamespace, Name: saName},
			currentServiceAccount)).To(Succeed())
	})

	It("deployRoleRequestInCluster removes stale resources", func() {
		sveltosCluster := libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}

		prepareForTesting(&sveltosCluster)

		referecedResourceNamespace := randomString()

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: referecedResourceNamespace,
			},
		}

		Expect(testEnv.Create(context.TODO(), ns)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, ns)

		viewClusterRoleName := randomString()
		configMap1 := createConfigMapWithPolicy(referecedResourceNamespace, randomString(),
			fmt.Sprintf(viewClusterRole, viewClusterRoleName))

		viewRoleName := randomString()
		configMap2 := createConfigMapWithPolicy(referecedResourceNamespace, randomString(),
			fmt.Sprintf(viewRole, viewRoleName))

		Expect(testEnv.Create(context.TODO(), configMap1)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, configMap1)
		Expect(addTypeInformationToObject(scheme, configMap1)).To(Succeed())

		Expect(testEnv.Create(context.TODO(), configMap2)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, configMap2)
		Expect(addTypeInformationToObject(scheme, configMap2)).To(Succeed())

		roleRequest := getRoleRequest([]corev1.ConfigMap{*configMap1, *configMap2}, []corev1.Secret{},
			randomString(), randomString())
		Expect(testEnv.Create(context.TODO(), roleRequest)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, roleRequest)

		Expect(controllers.DeployRoleRequestInCluster(context.TODO(), testEnv.Client, sveltosCluster.Namespace,
			sveltosCluster.Name, roleRequest.Name, libsveltosv1alpha1.FeatureRoleRequest,
			libsveltosv1alpha1.ClusterTypeSveltos, deployer.Options{}, klogr.New())).To(Succeed())

		// Verify ClusterRole is present
		Eventually(func() bool {
			currentClusterRole := &rbacv1.ClusterRole{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Name: viewClusterRoleName},
				currentClusterRole)
			if err != nil {
				return false
			}
			return validateLabels(currentClusterRole, configMap1)
		}, timeout, pollingInterval).Should(BeTrue())

		// Name of the ServiceAccount created by Sveltos in the managed cluster
		saName := roles.GetServiceAccountNameInManagedCluster(
			roleRequest.Spec.ServiceAccountNamespace, roleRequest.Spec.ServiceAccountName)

		// Verify ClusterRoleBinding is present
		currentClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Name: viewClusterRoleName},
			currentClusterRoleBinding)).To(Succeed())
		Expect(currentClusterRoleBinding.Subjects).ToNot(BeNil())
		Expect(len(currentClusterRoleBinding.Subjects)).To(Equal(1))
		Expect(currentClusterRoleBinding.Subjects[0].Name).To(Equal(saName))
		Expect(currentClusterRoleBinding.Subjects[0].Namespace).To(Equal(controllers.ServiceAccountNamespace))

		// Verify Role is present
		Eventually(func() bool {
			currentRole := &rbacv1.Role{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: "default", Name: viewRoleName},
				currentRole)
			if err != nil {
				return false
			}
			return validateLabels(currentRole, configMap2)
		}, timeout, pollingInterval).Should(BeTrue())

		// Verify RoleBinding is present
		roleBinding := &rbacv1.RoleBinding{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Namespace: "default", Name: viewRoleName},
			roleBinding)).To(Succeed())
		Expect(roleBinding.Subjects).ToNot(BeNil())
		Expect(len(roleBinding.Subjects)).To(Equal(1))
		Expect(roleBinding.Subjects[0].Name).To(Equal(saName))
		Expect(roleBinding.Subjects[0].Namespace).To(Equal(controllers.ServiceAccountNamespace))

		// Verify ServiceAccount is present
		currentServiceAccount := &corev1.ServiceAccount{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Namespace: controllers.ServiceAccountNamespace, Name: saName},
			currentServiceAccount)).To(Succeed())

		// Update RoleRequest to not reference ConfigMap anymore
		currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}
		Expect(testEnv.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name},
			currentRoleRequest)).To(Succeed())
		currentRoleRequest.Spec.RoleRefs = make([]libsveltosv1alpha1.PolicyRef, 0)
		Expect(testEnv.Update(context.TODO(), currentRoleRequest)).To(Succeed())

		Eventually(func() bool {
			currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Name: roleRequest.Name},
				currentRoleRequest)
			if err != nil {
				return false
			}
			return len(currentRoleRequest.Spec.RoleRefs) == 0
		}, timeout, pollingInterval).Should(BeTrue())

		// Verify stale resources are gone
		Expect(controllers.DeployRoleRequestInCluster(context.TODO(), testEnv.Client, sveltosCluster.Namespace,
			sveltosCluster.Name, roleRequest.Name, libsveltosv1alpha1.FeatureRoleRequest,
			libsveltosv1alpha1.ClusterTypeSveltos, deployer.Options{}, klogr.New())).To(Succeed())

		// Verify ClusterRole is gone
		Eventually(func() bool {
			currentClusterRole := &rbacv1.ClusterRole{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Name: viewClusterRoleName},
				currentClusterRole)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())

		// Verify ClusterRoleBinding is gone
		Eventually(func() bool {
			currentClusterRoleBinding = &rbacv1.ClusterRoleBinding{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Name: viewClusterRoleName},
				currentClusterRoleBinding)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())
	})

	It("undeployRoleRequestFromCluster removes stale resources", func() {
		sveltosCluster := libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}

		prepareForTesting(&sveltosCluster)

		roleRequest := getRoleRequest([]corev1.ConfigMap{}, []corev1.Secret{},
			randomString(), randomString())
		Expect(testEnv.Create(context.TODO(), roleRequest)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, roleRequest)
		Expect(addTypeInformationToObject(scheme, roleRequest)).To(Succeed())

		viewClusterRoleName := randomString()
		clusterRole, err := utils.GetUnstructured([]byte(fmt.Sprintf(viewClusterRole, viewClusterRoleName)))
		Expect(err).To(BeNil())

		// Add labels and OwnerReference to pretend ClusterRole was created by RoleRequest

		// Add labels as objects deployed by sveltos must have those labels.
		// Sveltos wont clean up otherwise
		labels := map[string]string{
			deployer.ReferenceNameLabel:      randomString(),
			deployer.ReferenceNamespaceLabel: randomString(),
			deployer.ReferenceKindLabel:      "ConfigMap",
		}
		clusterRole.SetLabels(labels)

		apiVersion, kind := roleRequest.GetObjectKind().GroupVersionKind().ToAPIVersionAndKind()
		clusterRole.SetOwnerReferences([]metav1.OwnerReference{
			{APIVersion: apiVersion, Kind: kind, Name: roleRequest.GetName(), UID: roleRequest.GetUID()},
		})

		Expect(testEnv.Create(context.TODO(), clusterRole)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, clusterRole)
		Expect(addTypeInformationToObject(scheme, clusterRole)).To(Succeed())

		clusterRoleBinding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: clusterRole.GetName(),
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     clusterRole.GetKind(),
				Name:     viewClusterRoleName,
				APIGroup: "rbac.authorization.k8s.io",
			},
		}
		Expect(testEnv.Create(context.TODO(), clusterRoleBinding)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, clusterRoleBinding)

		Expect(controllers.UndeployRoleRequestFromCluster(context.TODO(), testEnv.Client, sveltosCluster.Namespace,
			sveltosCluster.Name, roleRequest.Name, libsveltosv1alpha1.FeatureRoleRequest,
			libsveltosv1alpha1.ClusterTypeSveltos, deployer.Options{}, klogr.New())).To(Succeed())

		// Verify ClusterRole is gone
		Eventually(func() bool {
			currentClusterRole := &rbacv1.ClusterRole{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Name: viewClusterRoleName},
				currentClusterRole)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())

		// Verify ClusterRoleBinding is gone
		Eventually(func() bool {
			currentClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Name: viewClusterRoleName},
				currentClusterRoleBinding)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())
	})

	It("undeployRoleRequestFromCluster removes secrets", func() {
		sveltosCluster := libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}

		prepareForTesting(&sveltosCluster)

		referecedResourceNamespace := randomString()

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: referecedResourceNamespace,
			},
		}

		Expect(testEnv.Create(context.TODO(), ns)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, ns)

		roleRequest := getRoleRequest([]corev1.ConfigMap{}, []corev1.Secret{},
			randomString(), randomString())
		Expect(testEnv.Create(context.TODO(), roleRequest)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, roleRequest)

		listOptions := []client.ListOption{
			client.InNamespace(sveltosCluster.Namespace),
		}
		secretList := &corev1.SecretList{}
		Expect(testEnv.List(context.TODO(), secretList, listOptions...)).To(Succeed())
		numberOfSecrets := len(secretList.Items)

		Expect(controllers.DeployRoleRequestInCluster(context.TODO(), testEnv.Client, sveltosCluster.Namespace,
			sveltosCluster.Name, roleRequest.Name, libsveltosv1alpha1.FeatureRoleRequest,
			libsveltosv1alpha1.ClusterTypeSveltos, deployer.Options{}, klogr.New())).To(Succeed())

		// Secret with kubeconfig for serviceAccount is created in the cluster namespace by above DeployRoleRequestInCluster
		Eventually(func() bool {
			secretList := &corev1.SecretList{}
			err := testEnv.List(context.TODO(), secretList, listOptions...)
			return err == nil && len(secretList.Items) == numberOfSecrets+1
		}, timeout, pollingInterval).Should(BeTrue())

		Expect(controllers.UndeployRoleRequestFromCluster(ctx, testEnv.Client, sveltosCluster.Namespace,
			sveltosCluster.Name, roleRequest.Name, libsveltosv1alpha1.FeatureRoleRequest,
			libsveltosv1alpha1.ClusterTypeSveltos, deployer.Options{}, klogr.New())).To(Succeed())

		// Secret with kubeconfig for serviceAccount is deleted in the cluster namespace by above UndeployRoleRequestFromCluster
		Eventually(func() bool {
			secretList := &corev1.SecretList{}
			err := testEnv.List(context.TODO(), secretList, listOptions...)
			return err == nil && len(secretList.Items) == numberOfSecrets
		}, timeout, pollingInterval).Should(BeTrue())

	})

	It("processRoleRequest detects roleRequest needs to be deployed in cluster", func() {
		dep := fakedeployer.GetClient(context.TODO(), klogr.New(), testEnv.Client)
		Expect(dep.RegisterFeatureID(libsveltosv1alpha1.FeatureRoleRequest)).To(Succeed())

		roleRequestReconciler := getRoleRequestReconciler(testEnv.Client, dep)
		roleRequest := getRoleRequest(nil, nil, randomString(), randomString())
		roleRequestScope := getRoleRequestScope(testEnv.Client, klogr.New(), roleRequest)

		sveltosCluster := libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}
		prepareForTesting(&sveltosCluster)

		f := controllers.GetHandlersForFeature(libsveltosv1alpha1.FeatureRoleRequest)
		clusterInfo, err := controllers.ProcessRoleRequest(roleRequestReconciler, context.TODO(),
			roleRequestScope, getClusterRef(&sveltosCluster), f, klogr.New())
		Expect(err).To(BeNil())
		Expect(clusterInfo).ToNot(BeNil())
		Expect(clusterInfo.Status).To(Equal(libsveltosv1alpha1.SveltosStatusProvisioning))
	})

	It("processRoleRequest detects RoleRequest does not need to be deployed in cluster", func() {
		dep := fakedeployer.GetClient(context.TODO(), klogr.New(), testEnv.Client)
		Expect(dep.RegisterFeatureID(libsveltosv1alpha1.FeatureRoleRequest)).To(Succeed())

		sveltosCluster := libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}
		prepareForTesting(&sveltosCluster)

		roleRequestReconciler := getRoleRequestReconciler(testEnv.Client, dep)
		roleRequest := getRoleRequest(nil, nil, randomString(), randomString())
		Expect(testEnv.Create(context.Background(), roleRequest))
		waitForObject(context.TODO(), testEnv.Client, roleRequest)

		hash, err := controllers.RoleRequestHash(context.TODO(), testEnv.Client, sveltosCluster.Namespace,
			roleRequest, klogr.New())
		Expect(err).To(BeNil())
		Expect(testEnv.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name}, roleRequest)).To(Succeed())
		roleRequest.Status = libsveltosv1alpha1.RoleRequestStatus{
			ClusterInfo: []libsveltosv1alpha1.ClusterInfo{
				{
					Cluster: corev1.ObjectReference{
						Namespace: sveltosCluster.Namespace, Name: sveltosCluster.Name,
						APIVersion: libsveltosv1alpha1.GroupVersion.String(),
						Kind:       libsveltosv1alpha1.SveltosClusterKind,
					},
					Status: libsveltosv1alpha1.SveltosStatusProvisioned,
					Hash:   hash,
				},
			},
		}
		Expect(testEnv.Status().Update(context.TODO(), roleRequest)).To(Succeed())

		Eventually(func() bool {
			err = testEnv.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name}, roleRequest)
			if err != nil {
				return false
			}
			return len(roleRequest.Status.ClusterInfo) == 1
		}, timeout, pollingInterval).Should(BeTrue())

		roleRequestScope := getRoleRequestScope(testEnv.Client, klogr.New(), roleRequest)

		f := controllers.GetHandlersForFeature(libsveltosv1alpha1.FeatureRoleRequest)
		clusterInfo, err := controllers.ProcessRoleRequest(roleRequestReconciler, context.TODO(),
			roleRequestScope, getClusterRef(&sveltosCluster), f, klogr.New())
		Expect(err).To(BeNil())
		Expect(clusterInfo).ToNot(BeNil())
		Expect(clusterInfo.Status).To(Equal(libsveltosv1alpha1.SveltosStatusProvisioned))
	})

	It("removeRoleRequest queue job to remove RoleRequest from Cluster", func() {
		dep := fakedeployer.GetClient(context.TODO(), klogr.New(), testEnv.Client)
		Expect(dep.RegisterFeatureID(libsveltosv1alpha1.FeatureRoleRequest)).To(Succeed())

		roleRequestReconciler := getRoleRequestReconciler(testEnv.Client, dep)
		roleRequest := getRoleRequest(nil, nil, randomString(), randomString())
		roleRequestScope := getRoleRequestScope(testEnv.Client, klogr.New(), roleRequest)

		sveltosCluster := libsveltosv1alpha1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}
		prepareForTesting(&sveltosCluster)

		Expect(testEnv.Create(context.TODO(), roleRequest)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, roleRequest)

		currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}
		Expect(testEnv.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name},
			currentRoleRequest)).To(Succeed())
		currentRoleRequest.Status.ClusterInfo = []libsveltosv1alpha1.ClusterInfo{
			{
				Cluster: corev1.ObjectReference{
					Namespace: sveltosCluster.Namespace, Name: sveltosCluster.Name,
					APIVersion: libsveltosv1alpha1.GroupVersion.String(), Kind: libsveltosv1alpha1.SveltosClusterKind,
				},
				Status: libsveltosv1alpha1.SveltosStatusProvisioned,
				Hash:   []byte(randomString()),
			},
		}

		Expect(testEnv.Status().Update(context.TODO(), currentRoleRequest)).To(Succeed())
		// Eventual loop so testEnv Cache is synced
		Eventually(func() bool {
			currentRoleRequest := &libsveltosv1alpha1.RoleRequest{}
			err := testEnv.Get(context.TODO(), types.NamespacedName{Name: roleRequest.Name},
				currentRoleRequest)
			return err == nil && len(currentRoleRequest.Status.ClusterInfo) == 1
		}, timeout, pollingInterval).Should(BeTrue())

		f := controllers.GetHandlersForFeature(libsveltosv1alpha1.FeatureRoleRequest)
		err := controllers.RemoveRoleRequest(roleRequestReconciler, context.TODO(), roleRequestScope,
			getClusterRef(&sveltosCluster), f, klogr.New())
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal("cleanup request is queued"))

		key := deployer.GetKey(sveltosCluster.Namespace, sveltosCluster.Name,
			roleRequest.Name, libsveltosv1alpha1.FeatureRoleRequest, libsveltosv1alpha1.ClusterTypeSveltos, true)
		Expect(dep.IsKeyInProgress(key)).To(BeTrue())
	})
})

func getClusterRef(cluster client.Object) *corev1.ObjectReference {
	apiVersion, kind := cluster.GetObjectKind().GroupVersionKind().ToAPIVersionAndKind()
	return &corev1.ObjectReference{
		Namespace:  cluster.GetNamespace(),
		Name:       cluster.GetName(),
		APIVersion: apiVersion,
		Kind:       kind,
	}
}
