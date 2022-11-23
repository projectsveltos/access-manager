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

package scope

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/cluster-api/util/patch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	libsveltosv1alpha1 "github.com/projectsveltos/libsveltos/api/v1alpha1"
)

// AccessRequestScopeParams defines the input parameters used to create a new AccessRequest Scope.
type AccessRequestScopeParams struct {
	Client         client.Client
	Logger         logr.Logger
	AccessRequest  *libsveltosv1alpha1.AccessRequest
	ControllerName string
}

// NewAccessRequestScope creates a new AccessRequest Scope from the supplied parameters.
// This is meant to be called for each reconcile iteration.
func NewAccessRequestScope(params AccessRequestScopeParams) (*AccessRequestScope, error) {
	if params.Client == nil {
		return nil, errors.New("client is required when creating a AccessRequestScope")
	}
	if params.AccessRequest == nil {
		return nil, errors.New("failed to generate new scope from nil AccessRequest")
	}

	helper, err := patch.NewHelper(params.AccessRequest, params.Client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to init patch helper")
	}
	return &AccessRequestScope{
		Logger:         params.Logger,
		client:         params.Client,
		AccessRequest:  params.AccessRequest,
		patchHelper:    helper,
		controllerName: params.ControllerName,
	}, nil
}

// AccessRequestScope defines the basic context for an actuator to operate upon.
type AccessRequestScope struct {
	logr.Logger
	client         client.Client
	patchHelper    *patch.Helper
	AccessRequest  *libsveltosv1alpha1.AccessRequest
	controllerName string
}

// PatchObject persists the feature configuration and status.
func (s *AccessRequestScope) PatchObject(ctx context.Context) error {
	return s.patchHelper.Patch(
		ctx,
		s.AccessRequest,
	)
}

// Close closes the current scope persisting the AccessRequest configuration and status.
func (s *AccessRequestScope) Close(ctx context.Context) error {
	return s.PatchObject(ctx)
}

// Name returns the AccessRequest name.
func (s *AccessRequestScope) Name() string {
	return s.AccessRequest.Name
}

// ControllerName returns the name of the controller that
// created the AccessRequestScope.
func (s *AccessRequestScope) ControllerName() string {
	return s.controllerName
}

// SetSecretRef sets the feature status.
func (s *AccessRequestScope) SetSecretRef(secretRef *corev1.ObjectReference) {
	s.AccessRequest.Status.SecretRef = secretRef
}

// SetFailureMessage sets the failure message
func (s *AccessRequestScope) SetFailureMessage(failureMessage *string) {
	s.AccessRequest.Status.FailureMessage = failureMessage
}
