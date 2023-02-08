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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2/klogr"

	"github.com/projectsveltos/access-manager/controllers"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	"github.com/projectsveltos/libsveltos/lib/deployer"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Deployer utils", func() {
	It("createServiceAccountInManagedCluster creates ServiceAccount", func() {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: controllers.ServiceAccountNamespace,
			},
		}
		initObjects := []client.Object{ns}

		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initObjects...).Build()

		name := randomString()
		roleRequest := getRoleRequest([]corev1.ConfigMap{}, []corev1.Secret{}, name)
		Expect(controllers.CreateServiceAccountInManagedCluster(context.TODO(), c, roleRequest)).To(Succeed())

		currentServiceAccount := &corev1.ServiceAccount{}
		Expect(c.Get(context.TODO(), types.NamespacedName{Namespace: controllers.ServiceAccountNamespace, Name: name},
			currentServiceAccount)).To(Succeed())

		Expect(deployer.IsOwnerReference(currentServiceAccount, roleRequest)).To(BeTrue())

		// returns no error when serviceAccount already exists
		Expect(controllers.CreateServiceAccountInManagedCluster(context.TODO(), c, roleRequest)).To(Succeed())
	})

	It("createNamespaceInManagedCluster creates ServiceAccount", func() {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()

		name := randomString()
		Expect(controllers.CreateNamespaceInManagedCluster(context.TODO(), c, name)).To(Succeed())

		currentNamespace := &corev1.Namespace{}
		Expect(c.Get(context.TODO(), types.NamespacedName{Name: name}, currentNamespace)).To(Succeed())

		// returns no error when namespace already exists
		Expect(controllers.CreateNamespaceInManagedCluster(context.TODO(), c, name)).To(Succeed())
	})

	It("collectReferencedObjects collects all existing referenced resources", func() {
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
			Type: libsveltosv1alpha1.ClusterProfileSecretType,
		}

		roleRequest := getRoleRequest([]corev1.ConfigMap{*configMap}, []corev1.Secret{*secret}, randomString())

		initObjects := []client.Object{roleRequest}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initObjects...).Build()

		// No errors when referenced resources do not exist
		refs, err := controllers.CollectReferencedObjects(context.TODO(), c, randomString(), roleRequest.Spec.RoleRefs, klogr.New())
		Expect(err).To(BeNil())
		Expect(len(refs)).To(BeZero())

		Expect(c.Create(context.TODO(), configMap)).To(Succeed())

		// No errors when subset of referenced resources do not exist
		refs, err = controllers.CollectReferencedObjects(context.TODO(), c, randomString(), roleRequest.Spec.RoleRefs, klogr.New())
		Expect(err).To(BeNil())
		Expect(len(refs)).To(Equal(1))

		Expect(c.Create(context.TODO(), secret)).To(Succeed())

		// No errors when all referenced resources exist
		refs, err = controllers.CollectReferencedObjects(context.TODO(), c, randomString(), roleRequest.Spec.RoleRefs, klogr.New())
		Expect(err).To(BeNil())
		Expect(len(refs)).To(Equal(2))
	})

	It("collectReferencedObjects collects all existing referenced resources gettting from cluster namespace", func() {
		clusterNamespace := randomString()

		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: clusterNamespace,
				Name:      randomString(),
			},
		}

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: clusterNamespace,
				Name:      randomString(),
			},
			Type: libsveltosv1alpha1.ClusterProfileSecretType,
		}

		roleRequest := getRoleRequest([]corev1.ConfigMap{*configMap}, []corev1.Secret{*secret}, randomString())
		// Reset the referenced resource namespaces
		for i := range roleRequest.Spec.RoleRefs {
			roleRequest.Spec.RoleRefs[i].Namespace = ""
		}

		initObjects := []client.Object{roleRequest}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(initObjects...).Build()

		// No errors when referenced resources do not exist
		refs, err := controllers.CollectReferencedObjects(context.TODO(), c, clusterNamespace, roleRequest.Spec.RoleRefs, klogr.New())
		Expect(err).To(BeNil())
		Expect(len(refs)).To(BeZero())

		Expect(c.Create(context.TODO(), configMap)).To(Succeed())

		// No errors when subset of referenced resources do not exist
		refs, err = controllers.CollectReferencedObjects(context.TODO(), c, clusterNamespace, roleRequest.Spec.RoleRefs, klogr.New())
		Expect(err).To(BeNil())
		Expect(len(refs)).To(Equal(1))

		Expect(c.Create(context.TODO(), secret)).To(Succeed())

		// No errors when all referenced resources exist
		refs, err = controllers.CollectReferencedObjects(context.TODO(), c, clusterNamespace, roleRequest.Spec.RoleRefs, klogr.New())
		Expect(err).To(BeNil())
		Expect(len(refs)).To(Equal(2))
	})

	It("getConfigMap returns configMap", func() {
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).Build()

		_, err := controllers.GetConfigMap(context.TODO(), c, types.NamespacedName{Namespace: configMap.Namespace, Name: configMap.Name})
		Expect(err).ToNot(BeNil())
		Expect(apierrors.IsNotFound(err)).To(BeTrue())

		Expect(c.Create(context.TODO(), configMap))

		var currentConfigMap *corev1.ConfigMap
		currentConfigMap, err = controllers.GetConfigMap(context.TODO(), c, types.NamespacedName{Namespace: configMap.Namespace, Name: configMap.Name})
		Expect(err).To(BeNil())
		Expect(currentConfigMap).ToNot(BeNil())
		Expect(currentConfigMap.Namespace).To(Equal(configMap.Namespace))
		Expect(currentConfigMap.Name).To(Equal(configMap.Name))
	})

	It("getSecret returns secret", func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
			Type: libsveltosv1alpha1.ClusterProfileSecretType,
		}

		c := fake.NewClientBuilder().WithScheme(scheme).Build()

		_, err := controllers.GetSecret(context.TODO(), c, types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name})
		Expect(err).ToNot(BeNil())
		Expect(apierrors.IsNotFound(err)).To(BeTrue())

		Expect(c.Create(context.TODO(), secret))

		var currentSecret *corev1.Secret
		currentSecret, err = controllers.GetSecret(context.TODO(), c, types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name})
		Expect(err).To(BeNil())
		Expect(currentSecret).ToNot(BeNil())
		Expect(currentSecret.Namespace).To(Equal(secret.Namespace))
		Expect(currentSecret.Name).To(Equal(secret.Name))
	})

	It("getSecret returns an error when type is different than ClusterProfileSecretType", func() {
		wrongSecretType := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
			Data: map[string][]byte{
				randomString(): []byte(randomString()),
			},
		}

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		Expect(c.Create(context.TODO(), wrongSecretType)).To(Succeed())

		secretName := types.NamespacedName{Namespace: wrongSecretType.Namespace, Name: wrongSecretType.Name}
		_, err := controllers.GetSecret(context.TODO(), c, secretName)
		Expect(err).ToNot(BeNil())
		Expect(err.Error()).To(Equal(libsveltosv1alpha1.ErrSecretTypeNotSupported.Error()))
	})

	It("deployReferencedResourceInManagedCluster deploys all resources contained in referenced ConfigMaps/Secrets", func() {
		referecedResourceNamespace := randomString()
		configMapName := randomString()
		secretName := randomString()

		viewClusterRoleName := randomString()
		configMap := createConfigMapWithPolicy(referecedResourceNamespace, configMapName, fmt.Sprintf(viewClusterRole, viewClusterRoleName))

		modifyClusterRoleName := randomString()
		secret := createSecretWithPolicy(referecedResourceNamespace, secretName, fmt.Sprintf(modifyClusterRole, modifyClusterRoleName))

		roleRequest := getRoleRequest([]corev1.ConfigMap{*configMap}, []corev1.Secret{*secret}, randomString())

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: referecedResourceNamespace,
			},
		}

		Expect(testEnv.Create(context.TODO(), ns)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, ns)

		Expect(testEnv.Create(context.TODO(), configMap)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, configMap)
		Expect(addTypeInformationToObject(scheme, configMap)).To(Succeed())

		Expect(testEnv.Create(context.TODO(), secret)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, secret)
		Expect(addTypeInformationToObject(scheme, secret)).To(Succeed())

		Expect(testEnv.Create(context.TODO(), roleRequest)).To(Succeed())
		waitForObject(context.TODO(), testEnv.Client, roleRequest)
		Expect(addTypeInformationToObject(scheme, roleRequest)).To(Succeed())

		deployedResources, err := controllers.DeployReferencedResourceInManagedCluster(context.TODO(),
			testEnv.Config, testEnv.Client, configMap, roleRequest, klogr.New())
		Expect(err).To(BeNil())
		Expect(deployedResources).ToNot(BeNil())
		Expect(len(deployedResources)).To(Equal(2))

		// Eventual loop so testEnv Cache is synced
		Eventually(func() bool {
			currentClusterRole := &rbacv1.ClusterRole{}
			err = testEnv.Get(context.TODO(),
				types.NamespacedName{Name: viewClusterRoleName},
				currentClusterRole)
			if err != nil {
				return false
			}
			return validateLabels(currentClusterRole, configMap)
		}, timeout, pollingInterval).Should(BeTrue())

		// Corresponding ClusterRoleBinding must be present
		Eventually(func() bool {
			currentClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
			err = testEnv.Get(context.TODO(),
				types.NamespacedName{Name: viewClusterRoleName},
				currentClusterRoleBinding)
			if err != nil {
				return false
			}
			return validateClusterRoleBinding(currentClusterRoleBinding, roleRequest)
		}, timeout, pollingInterval).Should(BeTrue())

		deployedResources, err = controllers.DeployReferencedResourceInManagedCluster(context.TODO(),
			testEnv.Config, testEnv.Client, secret, roleRequest, klogr.New())
		Expect(err).To(BeNil())
		Expect(deployedResources).ToNot(BeNil())
		Expect(len(deployedResources)).To(Equal(2))

		Eventually(func() bool {
			currentClusterRole := &rbacv1.ClusterRole{}
			err = testEnv.Get(context.TODO(),
				types.NamespacedName{Name: modifyClusterRoleName},
				currentClusterRole)
			if err != nil {
				return false
			}
			return validateLabels(currentClusterRole, secret)
		}, timeout, pollingInterval).Should(BeTrue())

		// Corresponding ClusterRoleBinding must be present
		Eventually(func() bool {
			currentClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
			err = testEnv.Get(context.TODO(),
				types.NamespacedName{Name: modifyClusterRoleName},
				currentClusterRoleBinding)
			if err != nil {
				return false
			}
			return validateClusterRoleBinding(currentClusterRoleBinding, roleRequest)
		}, timeout, pollingInterval).Should(BeTrue())
	})

	It("isClusterRoleOrRole returns true only for Role/ClusterRole", func() {
		configMap := createConfigMapWithPolicy(randomString(), configMapName, fmt.Sprintf(viewClusterRole, randomString()))
		Expect(addTypeInformationToObject(scheme, configMap)).To(Succeed())
		Expect(controllers.IsClusterRoleOrRole(configMap, klogr.New())).To(BeFalse())

		role := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: randomString(),
				Name:      randomString(),
			},
		}
		Expect(addTypeInformationToObject(scheme, &role)).To(Succeed())
		Expect(controllers.IsClusterRoleOrRole(&role, klogr.New())).To(BeTrue())

		clusterRole := rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: randomString(),
			},
		}
		Expect(addTypeInformationToObject(scheme, &clusterRole)).To(Succeed())
		Expect(controllers.IsClusterRoleOrRole(&clusterRole, klogr.New())).To(BeTrue())
	})

	It("getReferenceResourceNamespace returns the referenced resource namespace when set. cluster namespace otherwise.", func() {
		referecedResource := libsveltosv1alpha1.PolicyRef{
			Namespace: "",
			Name:      randomString(),
			Kind:      string(libsveltosv1alpha1.ConfigMapReferencedResourceKind),
		}

		clusterNamespace := randomString()
		Expect(controllers.GetReferenceResourceNamespace(clusterNamespace, referecedResource.Namespace)).To(
			Equal(clusterNamespace))

		referecedResource.Namespace = randomString()
		Expect(controllers.GetReferenceResourceNamespace(clusterNamespace, referecedResource.Namespace)).To(
			Equal(referecedResource.Namespace))
	})

})

func validateLabels(deployedResource, ownerResource client.Object) bool {
	labels := deployedResource.GetLabels()
	if labels == nil {
		return false
	}

	if !validateLabel(labels, deployer.ReferenceLabelKind, ownerResource.GetObjectKind().GroupVersionKind().Kind) {
		return false
	}

	if !validateLabel(labels, deployer.ReferenceLabelName, ownerResource.GetName()) {
		return false
	}

	if !validateLabel(labels, deployer.ReferenceLabelNamespace, ownerResource.GetNamespace()) {
		return false
	}

	return true
}

func validateLabel(labels map[string]string, key, value string) bool {
	v, ok := labels[key]
	if !ok {
		return false
	}
	return v == value
}

func validateClusterRoleBinding(clusterRoleBinding *rbacv1.ClusterRoleBinding,
	roleRequest *libsveltosv1alpha1.RoleRequest) bool {

	// ClusterRoleBinding name is set to ClusterRole name.
	// CLusterRoleBinding created for a given ClusterRole points to that ClusterRole
	if clusterRoleBinding.RoleRef.Name != clusterRoleBinding.Name {
		return false
	}

	if clusterRoleBinding.Subjects == nil {
		return false
	}

	if len(clusterRoleBinding.Subjects) != 1 {
		return false
	}

	if clusterRoleBinding.Subjects[0].Name != roleRequest.Spec.Admin {
		return false
	}

	if clusterRoleBinding.Subjects[0].Namespace != controllers.ServiceAccountNamespace {
		return false
	}

	return true
}
