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

package controllers

import (
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
)

// SveltosClusterPredicates predicates for sveltos Cluster. RoleRequestReconciler watches sveltos Cluster events
// and react to those by reconciling itself based on following predicates
func SveltosClusterPredicates(logger logr.Logger) predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			newCluster := e.ObjectNew.(*libsveltosv1alpha1.SveltosCluster)
			oldCluster := e.ObjectOld.(*libsveltosv1alpha1.SveltosCluster)
			log := logger.WithValues("predicate", "updateEvent",
				"namespace", newCluster.Namespace,
				"cluster", newCluster.Name,
			)

			if oldCluster == nil {
				log.V(logs.LogVerbose).Info("Old Cluster is nil. Reconcile RoleRequest")
				return true
			}

			// return true if Cluster.Spec.Paused has changed from true to false
			if oldCluster.Spec.Paused && !newCluster.Spec.Paused {
				log.V(logs.LogVerbose).Info(
					"Cluster was unpaused. Will attempt to reconcile associated RoleRequests.")
				return true
			}

			if !oldCluster.Status.Ready && newCluster.Status.Ready {
				log.V(logs.LogVerbose).Info(
					"Cluster was not ready. Will attempt to reconcile associated RoleRequests.")
				return true
			}

			if !reflect.DeepEqual(oldCluster.Labels, newCluster.Labels) {
				log.V(logs.LogVerbose).Info(
					"Cluster labels changed. Will attempt to reconcile associated RoleRequests.",
				)
				return true
			}

			// otherwise, return false
			log.V(logs.LogVerbose).Info(
				"Cluster did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.")
			return false
		},
		CreateFunc: func(e event.CreateEvent) bool {
			cluster := e.Object.(*libsveltosv1alpha1.SveltosCluster)
			log := logger.WithValues("predicate", "createEvent",
				"namespace", cluster.Namespace,
				"cluster", cluster.Name,
			)

			// Only need to trigger a reconcile if the Cluster.Spec.Paused is false
			if !cluster.Spec.Paused {
				log.V(logs.LogVerbose).Info(
					"Cluster is not paused.  Will attempt to reconcile associated RoleRequests.",
				)
				return true
			}
			log.V(logs.LogVerbose).Info(
				"Cluster did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.")
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			log := logger.WithValues("predicate", "deleteEvent",
				"namespace", e.Object.GetNamespace(),
				"cluster", e.Object.GetName(),
			)
			log.V(logs.LogVerbose).Info(
				"Cluster deleted.  Will attempt to reconcile associated RoleRequests.")
			return true
		},
		GenericFunc: func(e event.GenericEvent) bool {
			log := logger.WithValues("predicate", "genericEvent",
				"namespace", e.Object.GetNamespace(),
				"cluster", e.Object.GetName(),
			)
			log.V(logs.LogVerbose).Info(
				"Cluster did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.")
			return false
		},
	}
}

type ClusterPredicate struct {
	Logger logr.Logger
}

func (p ClusterPredicate) Create(obj event.TypedCreateEvent[*clusterv1.Cluster]) bool {
	log := p.Logger.WithValues("predicate", "createEvent",
		"namespace", obj.Object.Namespace,
		"cluster", obj.Object.Name,
	)

	// Only need to trigger a reconcile if the Cluster.Spec.Paused is false
	if !obj.Object.Spec.Paused {
		log.V(logs.LogVerbose).Info(
			"Cluster is not paused.  Will attempt to reconcile associated RoleRequests.",
		)
		return true
	}
	log.V(logs.LogVerbose).Info(
		"Cluster did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.")
	return false
}

func (p ClusterPredicate) Update(obj event.TypedUpdateEvent[*clusterv1.Cluster]) bool {
	newCluster := obj.ObjectNew
	oldCluster := obj.ObjectOld
	log := p.Logger.WithValues("predicate", "updateEvent",
		"namespace", newCluster.Namespace,
		"cluster", newCluster.Name,
	)

	if oldCluster == nil {
		log.V(logs.LogVerbose).Info("Old Cluster is nil. Reconcile RoleRequests.")
		return true
	}

	// return true if Cluster.Spec.Paused has changed from true to false
	if oldCluster.Spec.Paused && !newCluster.Spec.Paused {
		log.V(logs.LogVerbose).Info(
			"Cluster was unpaused. Will attempt to reconcile associated RoleRequests.")
		return true
	}

	if !reflect.DeepEqual(oldCluster.Labels, newCluster.Labels) {
		log.V(logs.LogVerbose).Info(
			"Cluster labels changed. Will attempt to reconcile associated RoleRequests.",
		)
		return true
	}

	// otherwise, return false
	log.V(logs.LogVerbose).Info(
		"Cluster did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.")
	return false
}

func (p ClusterPredicate) Delete(obj event.TypedDeleteEvent[*clusterv1.Cluster]) bool {
	log := p.Logger.WithValues("predicate", "deleteEvent",
		"namespace", obj.Object.GetNamespace(),
		"cluster", obj.Object.GetName(),
	)
	log.V(logs.LogVerbose).Info(
		"Cluster deleted.  Will attempt to reconcile associated RoleRequests.")
	return true
}

func (p ClusterPredicate) Generic(obj event.TypedGenericEvent[*clusterv1.Cluster]) bool {
	log := p.Logger.WithValues("predicate", "genericEvent",
		"namespace", obj.Object.GetNamespace(),
		"cluster", obj.Object.GetName(),
	)
	log.V(logs.LogVerbose).Info(
		"Cluster did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.")
	return false
}

// ConfigMapPredicates predicates for ConfigMaps. ClusterSummaryReconciler watches ConfigMap events
// and react to those by reconciling itself based on following predicates
func ConfigMapPredicates(logger logr.Logger) predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			newConfigMap := e.ObjectNew.(*corev1.ConfigMap)
			oldConfigMap := e.ObjectOld.(*corev1.ConfigMap)
			log := logger.WithValues("predicate", "updateEvent",
				"configmap", newConfigMap.Name,
			)

			if oldConfigMap == nil {
				log.V(logs.LogVerbose).Info("Old ConfigMap is nil. Reconcile RoleRequests.")
				return true
			}

			if !reflect.DeepEqual(oldConfigMap.Data, newConfigMap.Data) {
				log.V(logs.LogVerbose).Info(
					"ConfigMap Data changed. Will attempt to reconcile associated RoleRequests.",
				)
				return true
			}

			// otherwise, return false
			log.V(logs.LogVerbose).Info(
				"ConfigMap did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.")
			return false
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return CreateFuncTrue(e, logger)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return DeleteFuncTrue(e, logger)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return GenericFuncFalse(e, logger)
		},
	}
}

// SecretPredicates predicates for Secrets. ClusterSummaryReconciler watches Secret events
// and react to those by reconciling itself based on following predicates
func SecretPredicates(logger logr.Logger) predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			newSecret := e.ObjectNew.(*corev1.Secret)
			oldSecret := e.ObjectOld.(*corev1.Secret)
			log := logger.WithValues("predicate", "updateEvent",
				"secret", newSecret.Name,
			)

			if oldSecret == nil {
				log.V(logs.LogVerbose).Info("Old Secret is nil. Reconcile RoleRequests.")
				return true
			}

			if !reflect.DeepEqual(oldSecret.Data, newSecret.Data) {
				log.V(logs.LogVerbose).Info(
					"Secret Data changed. Will attempt to reconcile associated RoleRequests.",
				)
				return true
			}

			// otherwise, return false
			log.V(logs.LogVerbose).Info(
				"Secret did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.")
			return false
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return CreateFuncTrue(e, logger)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return DeleteFuncTrue(e, logger)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return GenericFuncFalse(e, logger)
		},
	}
}

var (
	CreateFuncTrue = func(e event.CreateEvent, logger logr.Logger) bool {
		log := logger.WithValues("predicate", "createEvent",
			e.Object.GetObjectKind(), e.Object.GetName(),
		)

		log.V(logs.LogVerbose).Info(fmt.Sprintf(
			"%s did match expected conditions.  Will attempt to reconcile associated RoleRequests.",
			e.Object.GetObjectKind()))
		return true
	}

	DeleteFuncTrue = func(e event.DeleteEvent, logger logr.Logger) bool {
		log := logger.WithValues("predicate", "deleteEvent",
			e.Object.GetObjectKind(), e.Object.GetName(),
		)
		log.V(logs.LogVerbose).Info(fmt.Sprintf(
			"%s did match expected conditions.  Will attempt to reconcile associated RoleRequests.",
			e.Object.GetObjectKind()))
		return true
	}

	GenericFuncFalse = func(e event.GenericEvent, logger logr.Logger) bool {
		log := logger.WithValues("predicate", "genericEvent",
			e.Object.GetObjectKind(), e.Object.GetName(),
		)
		log.V(logs.LogVerbose).Info(fmt.Sprintf(
			"%s did not match expected conditions.  Will not attempt to reconcile associated RoleRequests.",
			e.Object.GetObjectKind()))
		return false
	}
)
