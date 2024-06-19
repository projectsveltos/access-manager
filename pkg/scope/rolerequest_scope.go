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

package scope

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/cluster-api/util/patch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
)

// RoleRequestScopeParams defines the input parameters used to create a new RoleRequest Scope.
type RoleRequestScopeParams struct {
	Client         client.Client
	Logger         logr.Logger
	RoleRequest    *libsveltosv1beta1.RoleRequest
	ControllerName string
}

// NewRoleRequestScope creates a new RoleRequest Scope from the supplied parameters.
// This is meant to be called for each reconcile iteration.
func NewRoleRequestScope(params RoleRequestScopeParams) (*RoleRequestScope, error) {
	if params.Client == nil {
		return nil, errors.New("client is required when creating a RoleRequestScope")
	}
	if params.RoleRequest == nil {
		return nil, errors.New("failed to generate new scope from nil RoleRequest")
	}

	helper, err := patch.NewHelper(params.RoleRequest, params.Client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to init patch helper")
	}
	return &RoleRequestScope{
		Logger:         params.Logger,
		client:         params.Client,
		RoleRequest:    params.RoleRequest,
		patchHelper:    helper,
		controllerName: params.ControllerName,
	}, nil
}

// RoleRequestScope defines the basic context for an actuator to operate upon.
type RoleRequestScope struct {
	logr.Logger
	client         client.Client
	patchHelper    *patch.Helper
	RoleRequest    *libsveltosv1beta1.RoleRequest
	controllerName string
}

// PatchObject persists the feature configuration and status.
func (s *RoleRequestScope) PatchObject(ctx context.Context) error {
	return s.patchHelper.Patch(
		ctx,
		s.RoleRequest,
	)
}

// Close closes the current scope persisting the RoleRequest configuration and status.
func (s *RoleRequestScope) Close(ctx context.Context) error {
	return s.PatchObject(ctx)
}

// Name returns the RoleRequest name.
func (s *RoleRequestScope) Name() string {
	return s.RoleRequest.Name
}

// ControllerName returns the name of the controller that
// created the RoleRequestScope.
func (s *RoleRequestScope) ControllerName() string {
	return s.controllerName
}

// SetMatchingClusterRefs sets the MatchingClusterRefs status field
func (s *RoleRequestScope) SetMatchingClusterRefs(matchingClusterRefs []corev1.ObjectReference) {
	s.RoleRequest.Status.MatchingClusterRefs = matchingClusterRefs
}

// SetClusterInfo sets the ClusterInfo status field
func (s *RoleRequestScope) SetClusterInfo(clusterInfo []libsveltosv1beta1.ClusterInfo) {
	s.RoleRequest.Status.ClusterInfo = clusterInfo
}

// SetFailureMessage sets the failure message
func (s *RoleRequestScope) SetFailureMessage(failureMessage *string) {
	s.RoleRequest.Status.FailureMessage = failureMessage
}

// GetSelector returns the ClusterSelector
func (s *RoleRequestScope) GetSelector() *metav1.LabelSelector {
	return &s.RoleRequest.Spec.ClusterSelector.LabelSelector
}
