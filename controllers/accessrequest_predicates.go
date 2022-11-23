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

package controllers

import (
	"reflect"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
	logs "github.com/projectsveltos/libsveltos/lib/logsettings"
)

// IfNewDeletedOrSpecChange returns a predicate that returns true only if Spec changes or object is new/deleted
func IfNewDeletedOrSpecChange(logger logr.Logger) predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			newAccessRequest := e.ObjectNew.(*libsveltosv1alpha1.AccessRequest)
			oldAccessRequest := e.ObjectOld.(*libsveltosv1alpha1.AccessRequest)

			log := logger.WithValues("predicate", "updateEvent",
				"name", newAccessRequest.Name,
			)

			if oldAccessRequest == nil {
				logger.V(logs.LogInfo).Info("Old AccessRequest is nil. Reconcile AccessRequest")
				return true
			}

			// return true if AccessRequest.Status has changed
			if !reflect.DeepEqual(oldAccessRequest.Spec, newAccessRequest.Spec) {
				log.V(logs.LogInfo).Info(
					"AccessRequest Spec changed. Will attempt to reconcile associated AccessRequests.")
				return true
			}

			if !newAccessRequest.DeletionTimestamp.IsZero() && oldAccessRequest.DeletionTimestamp.IsZero() {
				log.V(logs.LogInfo).Info(
					"AccessRequest Deletion timestamp. Will attempt to reconcile associated AccessRequests.")
				return true
			}

			log.V(logs.LogInfo).Info(
				"AccessRequest did not match expected conditions.  Will attempt to reconcile associated AccessRequests.")
			return false
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}
}
