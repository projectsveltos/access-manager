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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
)

func (r *RoleRequestReconciler) requeueRoleRequestForReference(
	o client.Object,
) []reconcile.Request {

	logger := klogr.New().WithValues(
		"objectMapper",
		"requeueRoleRequestForReference",
		"reference",
		o.GetName(),
	)

	logger.V(logs.LogDebug).Info("reacting to configMap/secret change")

	r.Mux.Lock()
	defer r.Mux.Unlock()

	requests := make([]ctrl.Request, 0)

	// Namespace for referenced resources can be set or left empty.
	// When left empty Sveltos will search for a resource with proper kind/name
	// in the namespace of the cluster being programmed at the time.
	// So iterate twice. Once using the resource namespace. And once using
	// empty namespace
	namespaces := []string{o.GetNamespace(), ""}
	for i := range namespaces {
		// Following is needed as o.GetObjectKind().GroupVersionKind().Kind is not set
		var key corev1.ObjectReference
		switch o.(type) {
		case *corev1.ConfigMap:
			key = corev1.ObjectReference{
				APIVersion: corev1.SchemeGroupVersion.String(),
				Kind:       string(libsveltosv1alpha1.ConfigMapReferencedResourceKind),
				Namespace:  namespaces[i],
				Name:       o.GetName(),
			}
		case *corev1.Secret:
			key = corev1.ObjectReference{
				APIVersion: corev1.SchemeGroupVersion.String(),
				Kind:       string(libsveltosv1alpha1.SecretReferencedResourceKind),
				Namespace:  namespaces[i],
				Name:       o.GetName(),
			}
		default:
			key = corev1.ObjectReference{
				APIVersion: o.GetObjectKind().GroupVersionKind().GroupVersion().String(),
				Kind:       o.GetObjectKind().GroupVersionKind().Kind,
				Namespace:  namespaces[i],
				Name:       o.GetName(),
			}
		}

		logger.V(logs.LogDebug).Info(fmt.Sprintf("referenced key: %s", key))

		consumers := r.getReferenceMapForEntry(&key).Items()
		for i := range consumers {
			logger.V(logs.LogDebug).Info(fmt.Sprintf("requeue consumer: %s", consumers[i]))
			requests = append(requests, ctrl.Request{
				NamespacedName: client.ObjectKey{
					Name:      consumers[i].Name,
					Namespace: consumers[i].Namespace,
				},
			})
		}
	}

	return requests
}

// requeueRoleRequestForCluster is a handler.ToRequestsFunc to be used to enqueue requests for reconciliation
// for RoleRequest to update when its own Sveltos/CAPI Cluster gets updated.
func (r *RoleRequestReconciler) requeueRoleRequestForCluster(
	o client.Object,
) []reconcile.Request {

	cluster := o
	logger := klogr.New().WithValues(
		"objectMapper",
		"requeueRoleRequestForCluster",
		"namespace",
		cluster.GetNamespace(),
		"cluster",
		cluster.GetName(),
	)

	logger.V(logs.LogDebug).Info("reacting to Cluster change")

	r.Mux.Lock()
	defer r.Mux.Unlock()

	clusterInfo := getKeyFromObject(r.Scheme, cluster)
	// Get all ClusterSummaries for this cluster and reconcile those
	requests := make([]ctrl.Request, r.getClusterMapForEntry(clusterInfo).Len())
	consumers := r.getClusterMapForEntry(clusterInfo).Items()

	for i := range consumers {
		l := logger.WithValues("roleRequest", fmt.Sprintf("%s/%s", consumers[i].Namespace, consumers[i].Name))
		l.V(logs.LogDebug).Info("queuing roleRequest")
		requests[i] = ctrl.Request{
			NamespacedName: client.ObjectKey{
				Namespace: consumers[i].Namespace,
				Name:      consumers[i].Name,
			},
		}
	}

	// Iterate over all current RoleRequests and reconcile the RoleRequests now
	// matching the Cluster
	for k := range r.RoleRequests {
		clusterProfileSelector := r.RoleRequests[k]
		parsedSelector, _ := labels.Parse(string(clusterProfileSelector))
		if parsedSelector.Matches(labels.Set(cluster.GetLabels())) {
			l := logger.WithValues("roleRequest", k.Name)
			l.V(logs.LogDebug).Info("queuing roleRequest")
			requests = append(requests, ctrl.Request{
				NamespacedName: client.ObjectKey{
					Name: k.Name,
				},
			})
		}
	}

	return requests
}
