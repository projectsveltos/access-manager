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

var (
	UpdateSecret             = (*AccessRequestReconciler).updateSecret
	CreateRole               = (*AccessRequestReconciler).createRole
	CreateRoleBinding        = (*AccessRequestReconciler).createRoleBinding
	CreateServiceAccount     = (*AccessRequestReconciler).createServiceAccount
	CreateRoleAndRoleBinding = (*AccessRequestReconciler).createRoleAndRoleBinding
	GetClassifierPolicyRules = (*AccessRequestReconciler).getClassifierPolicyRules
	GetCACert                = (*AccessRequestReconciler).getCACert
	GenerateKubeconfig       = (*AccessRequestReconciler).generateKubeconfig
	HandleAccessRequest      = (*AccessRequestReconciler).handleAccessRequest
	AddFinalizer             = (*AccessRequestReconciler).addFinalizer
	Cleanup                  = (*AccessRequestReconciler).cleanup
)

var (
	RequeueRoleRequestForSveltosCluster = (*RoleRequestReconciler).requeueRoleRequestForSveltosCluster
	RequeueRoleRequestForReference      = (*RoleRequestReconciler).requeueRoleRequestForReference
	ProcessRoleRequest                  = (*RoleRequestReconciler).processRoleRequest
	RemoveRoleRequest                   = (*RoleRequestReconciler).removeRoleRequest
	GetMatchingClusters                 = (*RoleRequestReconciler).getMatchingClusters
	GetClosestExpirationTime            = (*RoleRequestReconciler).getClosestExpirationTime
)

const (
	ServiceAccountNamespace = serviceAccountNamespace
)

var (
	GetHandlersForFeature   = getHandlersForFeature
	CreatFeatureHandlerMaps = creatFeatureHandlerMaps
)

var (
	CreateServiceAccountInManagedCluster     = createServiceAccountInManagedCluster
	CreateNamespaceInManagedCluster          = createNamespaceInManagedCluster
	CollectReferencedObjects                 = collectReferencedObjects
	GetConfigMap                             = getConfigMap
	GetSecret                                = getSecret
	DeployReferencedResourceInManagedCluster = deployReferencedResourceInManagedCluster
	IsClusterRoleOrRole                      = isClusterRoleOrRole
	GetReferenceResourceNamespace            = getReferenceResourceNamespace
	IsTimeExpired                            = isTimeExpired
	CreateSecretWithKubeconfig               = createSecretWithKubeconfig
	GetSecretWithKubeconfig                  = getSecretWithKubeconfig
)

const (
	ExpirationKey = expirationKey
)

var (
	DeployRoleRequestInCluster     = deployRoleRequestInCluster
	UndeployRoleRequestFromCluster = undeployRoleRequestFromCluster
	RoleRequestHash                = roleRequestHash
)
