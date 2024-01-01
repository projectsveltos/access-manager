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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/projectsveltos/access-manager/controllers"
	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
)

var _ = Describe("AccessRequest Predicates: IfNewDeletedOrSpecChange", func() {
	var logger logr.Logger
	var accessRequest *libsveltosv1alpha1.AccessRequest

	BeforeEach(func() {
		logger = textlogger.NewLogger(textlogger.NewConfig(textlogger.Verbosity(1)))
		accessRequest = &libsveltosv1alpha1.AccessRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: randomString(),
			},
			Spec: libsveltosv1alpha1.AccessRequestSpec{
				Namespace: randomString(),
				Name:      randomString(),
				Type:      libsveltosv1alpha1.SveltosAgentRequest,
			},
		}
	})

	It("Create reprocesses", func() {
		accessRequestPredicate := controllers.IfNewDeletedOrSpecChange(logger)

		e := event.CreateEvent{
			Object: accessRequest,
		}

		result := accessRequestPredicate.Create(e)
		Expect(result).To(BeTrue())
	})

	It("Delete reprocesses", func() {
		accessRequestPredicate := controllers.IfNewDeletedOrSpecChange(logger)

		e := event.DeleteEvent{
			Object: accessRequest,
		}

		result := accessRequestPredicate.Delete(e)
		Expect(result).To(BeTrue())
	})

	It("Update does not reprocess when Spec is same", func() {
		accessRequestPredicate := controllers.IfNewDeletedOrSpecChange(logger)

		oldAccessRequest := *accessRequest
		e := event.UpdateEvent{
			ObjectOld: &oldAccessRequest,
			ObjectNew: accessRequest,
		}

		result := accessRequestPredicate.Update(e)
		Expect(result).To(BeFalse())
	})
})
