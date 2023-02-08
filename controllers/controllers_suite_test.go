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
	"fmt"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectsveltos/access-manager/controllers"
	"github.com/projectsveltos/access-manager/internal/test/helpers"
	"github.com/projectsveltos/access-manager/pkg/scope"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	"github.com/projectsveltos/libsveltos/lib/crd"
	"github.com/projectsveltos/libsveltos/lib/deployer"
	libsveltosset "github.com/projectsveltos/libsveltos/lib/set"
	"github.com/projectsveltos/libsveltos/lib/utils"
)

var (
	testEnv *helpers.TestEnvironment
	cancel  context.CancelFunc
	ctx     context.Context
	scheme  *runtime.Scheme
)

const (
	timeout         = 40 * time.Second
	pollingInterval = 2 * time.Second
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controllers Suite")
}

var _ = BeforeSuite(func() {
	By("bootstrapping test environment")

	ctx, cancel = context.WithCancel(context.TODO())

	var err error
	scheme, err = setupScheme()
	Expect(err).To(BeNil())

	testEnvConfig := helpers.NewTestEnvironmentConfiguration([]string{}, scheme)
	testEnv, err = testEnvConfig.Build(scheme)
	if err != nil {
		panic(err)
	}

	controllers.CreatFeatureHandlerMaps()

	go func() {
		By("Starting the manager")
		err = testEnv.StartManager(ctx)
		if err != nil {
			panic(fmt.Sprintf("Failed to start the envtest manager: %v", err))
		}
	}()

	accessRequestCRD, err := utils.GetUnstructured(crd.GetAccessRequestCRDYAML())
	Expect(err).To(BeNil())
	Expect(testEnv.Create(ctx, accessRequestCRD)).To(Succeed())
	waitForObject(context.TODO(), testEnv.Client, accessRequestCRD)

	roleRequestCRD, err := utils.GetUnstructured(crd.GetRoleRequestCRDYAML())
	Expect(err).To(BeNil())
	Expect(testEnv.Create(ctx, roleRequestCRD)).To(Succeed())
	waitForObject(context.TODO(), testEnv.Client, roleRequestCRD)

	sveltosClusterCRD, err := utils.GetUnstructured(crd.GetSveltosClusterCRDYAML())
	Expect(err).To(BeNil())
	Expect(testEnv.Create(ctx, sveltosClusterCRD)).To(Succeed())
	waitForObject(context.TODO(), testEnv.Client, sveltosClusterCRD)

	if synced := testEnv.GetCache().WaitForCacheSync(ctx); !synced {
		time.Sleep(time.Second)
	}
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})

func setupScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := libsveltosv1alpha1.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := clusterv1.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := apiextensionsv1.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := rbacv1.AddToScheme(s); err != nil {
		return nil, err
	}
	return s, nil
}

func randomString() string {
	const length = 10
	return util.RandomString(length)
}

// waitForObject waits for the cache to be updated helps in preventing test flakes due to the cache sync delays.
func waitForObject(ctx context.Context, c client.Client, obj client.Object) {
	// Makes sure the cache is updated with the new object
	objCopy := obj.DeepCopyObject().(client.Object)
	key := client.ObjectKeyFromObject(obj)

	// Eventual loop so testEnv Cache is synced
	Eventually(func() error {
		return c.Get(ctx, key, objCopy)
	}, timeout, pollingInterval).Should(BeNil())
}

func getAccessRequest(namespace, name string) *libsveltosv1alpha1.AccessRequest {
	return &libsveltosv1alpha1.AccessRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: libsveltosv1alpha1.AccessRequestSpec{
			Namespace: namespace,
			Name:      name + "-classifier-agent",
			Type:      libsveltosv1alpha1.ClassifierAgentRequest,
			ControlPlaneEndpoint: clusterv1.APIEndpoint{
				Host: "https://192.168.10.1",
				Port: int32(6443),
			},
		},
	}
}

func getRoleRequestReconciler(c client.Client, dep deployer.DeployerInterface) *controllers.RoleRequestReconciler {
	return &controllers.RoleRequestReconciler{
		Client:                  c,
		Scheme:                  scheme,
		Deployer:                dep,
		RoleRequests:            make(map[corev1.ObjectReference]libsveltosv1alpha1.Selector),
		ClusterMap:              make(map[corev1.ObjectReference]*libsveltosset.Set),
		RoleRequestClusterMap:   make(map[corev1.ObjectReference]*libsveltosset.Set),
		ReferenceMap:            make(map[corev1.ObjectReference]*libsveltosset.Set),
		RoleRequestReferenceMap: make(map[corev1.ObjectReference]*libsveltosset.Set),
		Mux:                     sync.Mutex{},
	}
}

func getRoleRequestScope(c client.Client, logger logr.Logger,
	roleRequest *libsveltosv1alpha1.RoleRequest) *scope.RoleRequestScope {

	classifierScope, err := scope.NewRoleRequestScope(scope.RoleRequestScopeParams{
		Client:         c,
		Logger:         logger,
		RoleRequest:    roleRequest,
		ControllerName: "rolerequest",
	})
	Expect(err).To(BeNil())
	return classifierScope
}

func addTypeInformationToObject(scheme *runtime.Scheme, obj client.Object) error {
	gvks, _, err := scheme.ObjectKinds(obj)
	if err != nil {
		return fmt.Errorf("missing apiVersion or kind and cannot assign it; %w", err)
	}

	for _, gvk := range gvks {
		if gvk.Kind == "" {
			continue
		}
		if gvk.Version == "" || gvk.Version == runtime.APIVersionInternal {
			continue
		}
		obj.GetObjectKind().SetGroupVersionKind(gvk)
		break
	}

	return nil
}

// createConfigMapWithPolicy creates a configMap with Data policies
func createConfigMapWithPolicy(namespace, configMapName string, policyStrs ...string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      configMapName,
		},
		Data: map[string]string{},
	}
	for i := range policyStrs {
		key := fmt.Sprintf("policy%d.yaml", i)
		if utf8.Valid([]byte(policyStrs[i])) {
			cm.Data[key] = policyStrs[i]
		} else {
			cm.BinaryData[key] = []byte(policyStrs[i])
		}
	}

	Expect(addTypeInformationToObject(scheme, cm)).To(Succeed())

	return cm
}

// createSecretWithPolicy creates a Secret with Data containing base64 encoded policies
func createSecretWithPolicy(namespace, configMapName string, policyStrs ...string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      configMapName,
		},
		Type: libsveltosv1alpha1.ClusterProfileSecretType,
		Data: map[string][]byte{},
	}
	for i := range policyStrs {
		key := fmt.Sprintf("policy%d.yaml", i)
		secret.Data[key] = []byte(policyStrs[i])
	}

	Expect(addTypeInformationToObject(scheme, secret)).To(Succeed())

	return secret
}

func getRoleRequest(configMaps []corev1.ConfigMap, secrets []corev1.Secret, admin string) *libsveltosv1alpha1.RoleRequest {
	roleRequest := libsveltosv1alpha1.RoleRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: randomString(),
		},
		Spec: libsveltosv1alpha1.RoleRequestSpec{
			RoleRefs: make([]libsveltosv1alpha1.PolicyRef, 0),
			Admin:    admin,
		},
	}

	for i := range configMaps {
		roleRequest.Spec.RoleRefs = append(roleRequest.Spec.RoleRefs, libsveltosv1alpha1.PolicyRef{
			Kind:      string(libsveltosv1alpha1.ConfigMapReferencedResourceKind),
			Namespace: configMaps[i].Namespace,
			Name:      configMaps[i].Name,
		})
	}

	for i := range secrets {
		roleRequest.Spec.RoleRefs = append(roleRequest.Spec.RoleRefs, libsveltosv1alpha1.PolicyRef{
			Kind:      string(libsveltosv1alpha1.SecretReferencedResourceKind),
			Namespace: secrets[i].Namespace,
			Name:      secrets[i].Name,
		})
	}

	return &roleRequest
}

// prepareForTesting creates following:
// - SveltosCluster (and its namespace)
// - secret containing kubeconfig to access CAPI Cluster
func prepareForTesting(cluster *libsveltosv1alpha1.SveltosCluster) {
	By("Create the secret with cluster kubeconfig")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cluster.Namespace,
			Name:      cluster.Name + "-sveltos-kubeconfig",
		},
		Data: map[string][]byte{
			"data": testEnv.Kubeconfig,
		},
	}

	By("Create the cluster's namespace")
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: cluster.Namespace,
		},
	}

	Expect(testEnv.Client.Create(context.TODO(), ns)).To(Succeed())
	waitForObject(context.TODO(), testEnv.Client, ns)

	Expect(testEnv.Client.Create(context.TODO(), cluster)).To(Succeed())
	waitForObject(context.TODO(), testEnv.Client, cluster)
	Expect(addTypeInformationToObject(scheme, cluster)).To(Succeed())

	// Set cluster ready
	currentCluster := &libsveltosv1alpha1.SveltosCluster{}
	Expect(testEnv.Client.Get(context.TODO(),
		types.NamespacedName{Namespace: cluster.Namespace, Name: cluster.Name}, currentCluster)).To(Succeed())
	currentCluster.Status.Ready = true
	Expect(testEnv.Status().Update(context.TODO(), currentCluster)).To(Succeed())

	Expect(testEnv.Client.Create(context.TODO(), secret)).To(Succeed())
	waitForObject(context.TODO(), testEnv.Client, secret)
}
