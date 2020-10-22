//  Copyright 2020 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package v2

import (
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumEgressRoute is a kubernetes Custom Resource that contains a spec
// to select pods so that they have consistent egress IP.
type CiliumEgressRoute struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is desired state of the egress route
	Spec CiliumEgressRouteSpec `json:"spec,omitempty"`

	Status CiliumEgressRouteStatus `json:"status"`
}

// CiliumEgressRouteSpec ...
type CiliumEgressRouteSpec struct {
	// Egress ...
	Egress CiliumEgressEndpointSelectors `json:"egress,omitempty"`

	// EgressSourceIP ...
	EgressSourceIP string `json:"egressSourceIP"`
}

// CiliumEgressEndpointSelector ...
type CiliumEgressEndpointSelector struct {
	// NamespaceSelector ...
	NamespaceSelector *slim_metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector ...
	PodSelector *slim_metav1.LabelSelector `json:"podSelector,omitempty"`
}

// CiliumEgressEndpointSelectors ...
type CiliumEgressEndpointSelectors []CiliumEgressEndpointSelector

// CiliumEgressRouteStatus ...
type CiliumEgressRouteStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumEgressRouteList is a list of CiliumEgressRoute objects.
type CiliumEgressRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of ClusterwideLocalDirectPolicy.
	Items []CiliumEgressRoute `json:"items"`
}
