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
	"encoding/base64"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/textlogger"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/projectsveltos/access-manager/controllers"
	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
)

const (
	viewClusterRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["get", "watch", "list"]`

	modifyClusterRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["*"]`

	viewRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %s
  namespace: default
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["get", "watch", "list"]`
)

var _ = Describe("RoleRequest Predicates: ConfigMapPredicates", func() {
	var logger logr.Logger
	var configMap *corev1.ConfigMap

	BeforeEach(func() {
		logger = textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1)))
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: randomString(),
			},
		}
	})

	It("Create returns true", func() {
		configMapPredicate := controllers.ConfigMapPredicates(logger)

		e := event.CreateEvent{
			Object: configMap,
		}

		result := configMapPredicate.Create(e)
		Expect(result).To(BeTrue())
	})

	It("Delete returns true", func() {
		configMapPredicate := controllers.ConfigMapPredicates(logger)

		e := event.DeleteEvent{
			Object: configMap,
		}

		result := configMapPredicate.Delete(e)
		Expect(result).To(BeTrue())
	})

	It("Update returns true when data has changed", func() {
		configMapPredicate := controllers.ConfigMapPredicates(logger)
		configMap.Data = map[string]string{"change": "now"}

		oldConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: configMap.Name,
			},
		}

		e := event.UpdateEvent{
			ObjectNew: configMap,
			ObjectOld: oldConfigMap,
		}

		result := configMapPredicate.Update(e)
		Expect(result).To(BeTrue())
	})

	It("Update returns false when Data has not changed", func() {
		configMapPredicate := controllers.ConfigMapPredicates(logger)
		configMap = createConfigMapWithPolicy("default", configMap.Name, fmt.Sprintf(viewClusterRole, randomString()))

		oldConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:   configMap.Name,
				Labels: map[string]string{"env": "testing"},
			},
			Data: configMap.Data,
		}

		e := event.UpdateEvent{
			ObjectNew: configMap,
			ObjectOld: oldConfigMap,
		}

		result := configMapPredicate.Update(e)
		Expect(result).To(BeFalse())
	})
})

var _ = Describe("RoleRequest Predicates: SecretPredicates", func() {
	var logger logr.Logger
	var secret *corev1.Secret

	BeforeEach(func() {
		logger = textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1)))

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: randomString(),
			},
		}
	})

	It("Create returns true", func() {
		secretPredicate := controllers.SecretPredicates(logger)

		e := event.CreateEvent{
			Object: secret,
		}

		result := secretPredicate.Create(e)
		Expect(result).To(BeTrue())
	})

	It("Delete returns true", func() {
		secretPredicate := controllers.SecretPredicates(logger)

		e := event.DeleteEvent{
			Object: secret,
		}

		result := secretPredicate.Delete(e)
		Expect(result).To(BeTrue())
	})

	It("Update returns true when data has changed", func() {
		secretPredicate := controllers.SecretPredicates(logger)
		str := base64.StdEncoding.EncodeToString([]byte("password"))
		secret.Data = map[string][]byte{"change": []byte(str)}

		oldSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secret.Name,
			},
		}

		e := event.UpdateEvent{
			ObjectNew: secret,
			ObjectOld: oldSecret,
		}

		result := secretPredicate.Update(e)
		Expect(result).To(BeTrue())
	})

	It("Update returns false when Data has not changed", func() {
		secretPredicate := controllers.SecretPredicates(logger)

		oldSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:   secret.Name,
				Labels: map[string]string{"env": "testing"},
			},
		}

		e := event.UpdateEvent{
			ObjectNew: secret,
			ObjectOld: oldSecret,
		}

		result := secretPredicate.Update(e)
		Expect(result).To(BeFalse())
	})
})

var _ = Describe("RoleRequest Predicates: SvelotsClusterPredicates", func() {
	var logger logr.Logger
	var cluster *libsveltosv1beta1.SveltosCluster

	const (
		upstreamClusterNamePrefix = "upstream-sveltoscluster"
	)

	BeforeEach(func() {
		logger = textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1)))

		cluster = &libsveltosv1beta1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      upstreamClusterNamePrefix + randomString(),
				Namespace: "sc-predicates" + randomString(),
			},
		}
	})

	It("Create reprocesses when sveltos Cluster is unpaused", func() {
		clusterPredicate := controllers.SveltosClusterPredicates(logger)

		cluster.Spec.Paused = false

		e := event.CreateEvent{
			Object: cluster,
		}

		result := clusterPredicate.Create(e)
		Expect(result).To(BeTrue())
	})
	It("Create does not reprocess when sveltos Cluster is paused", func() {
		clusterPredicate := controllers.SveltosClusterPredicates(logger)

		cluster.Spec.Paused = true
		cluster.Annotations = map[string]string{clusterv1.PausedAnnotation: "true"}

		e := event.CreateEvent{
			Object: cluster,
		}

		result := clusterPredicate.Create(e)
		Expect(result).To(BeFalse())
	})
	It("Delete does reprocess ", func() {
		clusterPredicate := controllers.SveltosClusterPredicates(logger)

		e := event.DeleteEvent{
			Object: cluster,
		}

		result := clusterPredicate.Delete(e)
		Expect(result).To(BeTrue())
	})
	It("Update reprocesses when sveltos Cluster paused changes from true to false", func() {
		clusterPredicate := controllers.SveltosClusterPredicates(logger)

		cluster.Spec.Paused = false

		oldCluster := &libsveltosv1beta1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		}
		oldCluster.Spec.Paused = true
		oldCluster.Annotations = map[string]string{clusterv1.PausedAnnotation: "true"}

		e := event.UpdateEvent{
			ObjectNew: cluster,
			ObjectOld: oldCluster,
		}

		result := clusterPredicate.Update(e)
		Expect(result).To(BeTrue())
	})
	It("Update does not reprocess when sveltos Cluster paused changes from false to true", func() {
		clusterPredicate := controllers.SveltosClusterPredicates(logger)

		cluster.Spec.Paused = true
		cluster.Annotations = map[string]string{clusterv1.PausedAnnotation: "true"}
		oldCluster := &libsveltosv1beta1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		}
		oldCluster.Spec.Paused = false

		e := event.UpdateEvent{
			ObjectNew: cluster,
			ObjectOld: oldCluster,
		}

		result := clusterPredicate.Update(e)
		Expect(result).To(BeFalse())
	})
	It("Update does not reprocess when sveltos Cluster paused has not changed", func() {
		clusterPredicate := controllers.SveltosClusterPredicates(logger)

		cluster.Spec.Paused = false
		oldCluster := &libsveltosv1beta1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		}
		oldCluster.Spec.Paused = false

		e := event.UpdateEvent{
			ObjectNew: cluster,
			ObjectOld: oldCluster,
		}

		result := clusterPredicate.Update(e)
		Expect(result).To(BeFalse())
	})
	It("Update reprocesses when sveltos Cluster labels change", func() {
		clusterPredicate := controllers.SveltosClusterPredicates(logger)

		cluster.Labels = map[string]string{"department": "eng"}

		oldCluster := &libsveltosv1beta1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
				Labels:    map[string]string{},
			},
		}

		e := event.UpdateEvent{
			ObjectNew: cluster,
			ObjectOld: oldCluster,
		}

		result := clusterPredicate.Update(e)
		Expect(result).To(BeTrue())
	})
	It("Update reprocesses when sveltos Cluster Status Ready changes", func() {
		clusterPredicate := controllers.SveltosClusterPredicates(logger)

		cluster.Status.Ready = true

		oldCluster := &libsveltosv1beta1.SveltosCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
				Labels:    map[string]string{},
			},
			Status: libsveltosv1beta1.SveltosClusterStatus{
				Ready: false,
			},
		}

		e := event.UpdateEvent{
			ObjectNew: cluster,
			ObjectOld: oldCluster,
		}

		result := clusterPredicate.Update(e)
		Expect(result).To(BeTrue())
	})
})

var _ = Describe("RoleRequest Predicates: ClusterPredicates", func() {
	var logger logr.Logger
	var cluster *clusterv1.Cluster
	var (
		paused   = true
		unpaused = false
	)

	const (
		upstreamClusterNamePrefix = "upstream-cluster"
	)

	BeforeEach(func() {
		logger = textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1)))

		cluster = &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      upstreamClusterNamePrefix + randomString(),
				Namespace: "c-predicates" + randomString(),
			},
		}
	})

	It("Create reprocesses when v1Cluster is unpaused", func() {
		clusterPredicate := controllers.ClusterPredicate{Logger: logger}

		cluster.Spec.Paused = &unpaused

		result := clusterPredicate.Create(event.TypedCreateEvent[*clusterv1.Cluster]{Object: cluster})
		Expect(result).To(BeTrue())
	})
	It("Create does not reprocess when v1Cluster is paused", func() {
		clusterPredicate := controllers.ClusterPredicate{Logger: logger}

		cluster.Spec.Paused = &paused
		cluster.Annotations = map[string]string{clusterv1.PausedAnnotation: "true"}

		result := clusterPredicate.Create(event.TypedCreateEvent[*clusterv1.Cluster]{Object: cluster})
		Expect(result).To(BeFalse())
	})
	It("Delete does reprocess ", func() {
		clusterPredicate := controllers.ClusterPredicate{Logger: logger}

		result := clusterPredicate.Delete(event.TypedDeleteEvent[*clusterv1.Cluster]{Object: cluster})
		Expect(result).To(BeTrue())
	})
	It("Update reprocesses when v1Cluster paused changes from true to false", func() {
		clusterPredicate := controllers.ClusterPredicate{Logger: logger}

		cluster.Spec.Paused = &unpaused

		oldCluster := &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		}
		oldCluster.Spec.Paused = &paused
		oldCluster.Annotations = map[string]string{clusterv1.PausedAnnotation: "true"}

		result := clusterPredicate.Update(event.TypedUpdateEvent[*clusterv1.Cluster]{
			ObjectNew: cluster, ObjectOld: oldCluster})
		Expect(result).To(BeTrue())
	})
	It("Update does not reprocess when v1Cluster paused changes from false to true", func() {
		clusterPredicate := controllers.ClusterPredicate{Logger: logger}

		cluster.Spec.Paused = &paused
		cluster.Annotations = map[string]string{clusterv1.PausedAnnotation: "true"}
		oldCluster := &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		}
		oldCluster.Spec.Paused = &unpaused

		result := clusterPredicate.Update(event.TypedUpdateEvent[*clusterv1.Cluster]{
			ObjectNew: cluster, ObjectOld: oldCluster})
		Expect(result).To(BeFalse())
	})
	It("Update does not reprocess when v1Cluster paused has not changed", func() {
		clusterPredicate := controllers.ClusterPredicate{Logger: logger}

		cluster.Spec.Paused = &unpaused
		oldCluster := &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		}
		oldCluster.Spec.Paused = &unpaused

		result := clusterPredicate.Update(event.TypedUpdateEvent[*clusterv1.Cluster]{
			ObjectNew: cluster, ObjectOld: oldCluster})
		Expect(result).To(BeFalse())
	})
	It("Update reprocesses when v1Cluster labels change", func() {
		clusterPredicate := controllers.ClusterPredicate{Logger: logger}

		cluster.Labels = map[string]string{"department": "eng"}

		oldCluster := &clusterv1.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
				Labels:    map[string]string{},
			},
		}

		result := clusterPredicate.Update(event.TypedUpdateEvent[*clusterv1.Cluster]{
			ObjectNew: cluster, ObjectOld: oldCluster})
		Expect(result).To(BeTrue())
	})
})
