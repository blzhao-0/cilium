// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egress

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/types"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-egress")

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	// TODO(ygui)
	MaxEntries = 512000

	// Name is the canonical name for the Egress map on the filesystem.
	Name = "cilium_egress"
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct egress_key in <bpf/lib/maps.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key struct {
	Pad1   uint16 `align:"pad1"`
	Pad2   uint8  `align:"pad2"`
	Family uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"` // TODO: union0?
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k Key) NewValue() bpf.MapValue { return &EgressEndpointInfo{} }

func (k Key) String() string {
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		ipStr := net.IP(k.IP[:net.IPv4len]).String()
		return fmt.Sprintf("%s", ipStr)
	case bpf.EndpointKeyIPv6:
		ipStr := k.IP.String()
		return fmt.Sprintf("%s", ipStr)
	}
	return "<unknown>"
}

// NewKey returns an Key based on the provided IP address and mask. The address
// family is automatically detected
func NewKey(ip net.IP) Key {
	result := Key{}

	if ip4 := ip.To4(); ip4 != nil {
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}

	return result
}

// EgressEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type EgressEndpointInfo struct {
	EgressIP         types.IPv6 `align:"$union0"`
	Family           uint8      `align:"family"`
	Key              uint8      `align:"key"`
	Pad              uint16     `align:"pad"`
	SecurityIdentity uint32     `align:"sec_label"`
	TunnelEndpoint   types.IPv4 `align:"tunnel_endpoint"`
}

func (v *EgressEndpointInfo) String() string {
	var (
		ipStr = "<unknown>"
	)

	switch v.Family {
	case bpf.EndpointKeyIPv4:
		ipStr = net.IP(v.EgressIP[:net.IPv4len]).String()
	case bpf.EndpointKeyIPv6:
		ipStr = v.EgressIP.String()
	}

	return fmt.Sprintf("%d %d %s %s", v.SecurityIdentity, v.Key, v.TunnelEndpoint, ipStr)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *EgressEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// Map represents an Egress BPF map.
type Map struct {
	bpf.Map

	// detectDeleteSupport is used to initialize 'supportsDelete' the first
	// time that a delete is issued from the datapath.
	detectDeleteSupport sync.Once

	// deleteSupport is set to 'true' initially, then is updated to set
	// whether the underlying kernel supports delete operations on the map
	// the first time that supportsDelete() is called.
	deleteSupport bool
}

// NewMap instantiates a Map.
func NewMap(name string) *Map {
	return &Map{
		Map: *bpf.NewMap(
			name,
			bpf.MapTypeHash,
			&Key{},
			int(unsafe.Sizeof(Key{})),
			&EgressEndpointInfo{},
			int(unsafe.Sizeof(EgressEndpointInfo{})),
			MaxEntries,
			bpf.BPF_F_NO_PREALLOC, 0,
			bpf.ConvertKeyValue,
		).WithCache(),
		deleteSupport: true,
	}
}

var (
	// Egress is a mapping of all endpoint source IPs in the cluster which this
	// Cilium agent is responsible to redirect to egress gateway.
	// It is a singleton; there is only one such map per agent.
	Egress = NewMap(Name)
)
