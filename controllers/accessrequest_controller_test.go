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

package controllers_test

import (
	"context"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/projectsveltos/access-manager/controllers"
	"github.com/projectsveltos/access-manager/pkg/scope"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
)

const (
	configMapNs   = "kube-system"
	configMapName = "kube-root-ca.crt"
	caCrtKey      = "ca.crt"
)

var _ = Describe("AccessRequestReconciler", func() {
	var accessRequest *libsveltosv1alpha1.AccessRequest
	var reconciler *controllers.AccessRequestReconciler
	var arScope *scope.AccessRequestScope

	BeforeEach(func() {
		reconciler = &controllers.AccessRequestReconciler{
			Client: testEnv.Client,
			Config: testEnv.Config,
			Scheme: scheme,
		}

		namespace := randomString()
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		}
		Expect(testEnv.Create(context.TODO(), ns))
		waitForObject(context.TODO(), testEnv.Client, ns)

		accessRequest = getAccessRequest(namespace, randomString())

		var err error
		arScope, err = scope.NewAccessRequestScope(scope.AccessRequestScopeParams{
			Client:         testEnv.Client,
			Logger:         textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1))),
			AccessRequest:  accessRequest,
			ControllerName: "accessRequest",
		})
		Expect(err).To(BeNil())
	})

	It("updateSecret creates secret", func() {
		kubeconfig := []byte(randomString())
		Expect(controllers.UpdateSecret(reconciler, context.TODO(), arScope, kubeconfig)).To(Succeed())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			currentSecret := &corev1.Secret{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				currentSecret)
		}, timeout, pollingInterval).Should(BeNil())

		currentSecret := &corev1.Secret{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
			currentSecret)).To(Succeed())
		Expect(currentSecret.Data).ToNot(BeNil())
		Expect(reflect.DeepEqual(currentSecret.Data["data"], kubeconfig)).To(BeTrue())
		Expect(currentSecret.Labels).ToNot(BeNil())
		_, ok := currentSecret.Labels[libsveltosv1alpha1.AccessRequestNameLabel]
		Expect(ok).To(BeTrue())
	})

	It("createRole creates Role", func() {
		rules := controllers.GetClassifierPolicyRules(reconciler)
		Expect(controllers.CreateRole(reconciler, context.TODO(), arScope, rules)).To(Succeed())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			currentRole := &rbacv1.Role{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				currentRole)
		}, timeout, pollingInterval).Should(BeNil())

		currentRole := &rbacv1.Role{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
			currentRole)).To(Succeed())
		Expect(reflect.DeepEqual(currentRole.Rules, rules)).To(BeTrue())
	})

	It("createRoleBinding creates RoleBinding", func() {
		Expect(controllers.CreateRoleBinding(reconciler, context.TODO(), arScope)).To(Succeed())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			currentRoleBinding := &rbacv1.RoleBinding{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				currentRoleBinding)
		}, timeout, pollingInterval).Should(BeNil())

		currentRoleBinding := &rbacv1.RoleBinding{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
			currentRoleBinding)).To(Succeed())
		Expect(currentRoleBinding.RoleRef.Name).To(Equal(accessRequest.Spec.Name))
		Expect(currentRoleBinding.RoleRef.Kind).To(Equal("Role"))
		Expect(currentRoleBinding.Subjects).ToNot(BeNil())
		Expect(len(currentRoleBinding.Subjects)).To(Equal(1))
		Expect(currentRoleBinding.Subjects[0].Name).To(Equal(accessRequest.Spec.Name))
		Expect(currentRoleBinding.Subjects[0].Namespace).To(Equal(accessRequest.Spec.Namespace))
		Expect(currentRoleBinding.Subjects[0].Kind).To(Equal("ServiceAccount"))
	})

	It("createServiceAccount creates ServiceAccount", func() {
		Expect(controllers.CreateServiceAccount(reconciler, context.TODO(), arScope)).To(Succeed())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			currentServiceAccount := &corev1.ServiceAccount{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				currentServiceAccount)
		}, timeout, pollingInterval).Should(BeNil())

		currentServiceAccount := &corev1.ServiceAccount{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
			currentServiceAccount)).To(Succeed())
	})

	It("createRoleAndRoleBinding creates Role and RoleBinding", func() {
		Expect(controllers.CreateRoleAndRoleBinding(reconciler, context.TODO(), arScope)).To(Succeed())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			currentRoleBinding := &rbacv1.RoleBinding{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				currentRoleBinding)
		}, timeout, pollingInterval).Should(BeNil())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			currentRole := &rbacv1.Role{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				currentRole)
		}, timeout, pollingInterval).Should(BeNil())
	})

	It("getCACert get cert from ConfigMap", func() {
		createCACrtConfigMap()

		configMap := &corev1.ConfigMap{}
		Expect(testEnv.Get(context.TODO(),
			types.NamespacedName{Namespace: configMapNs, Name: configMapName}, configMap)).To(Succeed())
		Expect(configMap.Data).ToNot(BeNil())
		cert, ok := configMap.Data[caCrtKey]
		Expect(ok).To(BeTrue())

		currentCert, err := controllers.GetCACert(reconciler, context.TODO())
		Expect(err).To(BeNil())
		Expect(currentCert).ToNot(BeNil())
		Expect(reflect.DeepEqual(currentCert, []byte(cert))).To(BeTrue())
	})

	It("generateKubeconfig returns Kubeconfig", func() {
		createCACrtConfigMap()

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: accessRequest.Spec.Namespace,
				Name:      accessRequest.Spec.Name,
			},
		}

		Expect(testEnv.Create(context.TODO(), sa))
		waitForObject(context.TODO(), testEnv.Client, sa)

		kubeconfig, err := controllers.GenerateKubeconfig(reconciler, context.TODO(), arScope)
		Expect(err).To(BeNil())
		Expect(kubeconfig).ToNot(BeNil())
	})

	It("handleAccessRequest creates ServiceAccount/Role/RoleBinding/Secret", func() {
		createCACrtConfigMap()

		Expect(controllers.HandleAccessRequest(reconciler, context.TODO(), arScope)).To(Succeed())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			sa := &corev1.ServiceAccount{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				sa)
		}, timeout, pollingInterval).Should(BeNil())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			role := &rbacv1.Role{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				role)
		}, timeout, pollingInterval).Should(BeNil())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			roleBinding := &rbacv1.RoleBinding{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				roleBinding)
		}, timeout, pollingInterval).Should(BeNil())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() error {
			secret := &corev1.Secret{}
			return testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				secret)
		}, timeout, pollingInterval).Should(BeNil())
	})

	It("addFinalizer adds finalizer to AccessRequest", func() {
		Expect(testEnv.Create(context.TODO(), accessRequest))
		waitForObject(context.TODO(), testEnv.Client, accessRequest)

		Expect(controllers.AddFinalizer(reconciler, context.TODO(), arScope)).To(Succeed())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() bool {
			ar := &libsveltosv1alpha1.AccessRequest{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Namespace, Name: accessRequest.Name},
				ar)
			if err != nil {
				return false
			}
			return controllerutil.ContainsFinalizer(ar, libsveltosv1alpha1.AccessRequestFinalizer)
		}, timeout, pollingInterval).Should(BeTrue())
	})

	It("cleanup removes ServiceAccount/Role/RoleBinding/Secret", func() {
		role := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      accessRequest.Spec.Name,
				Namespace: accessRequest.Spec.Namespace,
			},
		}
		Expect(testEnv.Create(context.TODO(), role))

		roleBinding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      accessRequest.Spec.Name,
				Namespace: accessRequest.Spec.Namespace,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     accessRequest.Spec.Name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      accessRequest.Spec.Name,
					Namespace: accessRequest.Spec.Namespace,
				},
			},
		}
		Expect(testEnv.Create(context.TODO(), roleBinding))

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      accessRequest.Spec.Name,
				Namespace: accessRequest.Spec.Namespace,
			},
		}
		Expect(testEnv.Create(context.TODO(), sa))

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      accessRequest.Spec.Name,
				Namespace: accessRequest.Spec.Namespace,
			},
		}
		Expect(testEnv.Create(context.TODO(), secret))

		waitForObject(context.TODO(), testEnv.Client, role)
		waitForObject(context.TODO(), testEnv.Client, sa)
		waitForObject(context.TODO(), testEnv.Client, secret)
		waitForObject(context.TODO(), testEnv.Client, roleBinding)

		logger := textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1)))
		Expect(controllers.Cleanup(reconciler, context.TODO(), arScope, logger)).To(Succeed())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() bool {
			sa := &corev1.ServiceAccount{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				sa)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() bool {
			role := &rbacv1.Role{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				role)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() bool {
			roleBinding := &rbacv1.RoleBinding{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				roleBinding)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())

		// Eventual loop so testEnv Cache is synced
		Eventually(func() bool {
			secret := &corev1.Secret{}
			err := testEnv.Get(context.TODO(),
				types.NamespacedName{Namespace: accessRequest.Spec.Namespace, Name: accessRequest.Spec.Name},
				secret)
			return err != nil && apierrors.IsNotFound(err)
		}, timeout, pollingInterval).Should(BeTrue())

	})
})

func createCACrtConfigMap() {
	cert := randomString()
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: configMapNs,
			Name:      configMapName,
		},
		Data: map[string]string{
			caCrtKey: cert,
		},
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapNs,
		},
	}
	err := testEnv.Create(context.TODO(), ns)
	if err != nil {
		Expect(apierrors.IsAlreadyExists(err)).To(BeTrue())
	}
	waitForObject(context.TODO(), testEnv.Client, ns)

	err = testEnv.Create(context.TODO(), configMap)
	if err != nil {
		Expect(apierrors.IsAlreadyExists(err)).To(BeTrue())
	}
	waitForObject(context.TODO(), testEnv.Client, configMap)
}
