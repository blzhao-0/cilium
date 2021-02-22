//  Copyright 2021 Authors of Cilium
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

// +build privileged_tests

package egresspolicy

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/k8s"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ManagerSuite struct {
	epm      *Manager
	svcCache k8s.ServiceCache
}

var _ = Suite(&ManagerSuite{})

type fakePodStore struct {
	OnList func() []interface{}
}

func (ps *fakePodStore) List() []interface{} {
	if ps.OnList != nil {
		return ps.OnList()
	}
	pods := make([]interface{}, 2, 2)
	pods = append(pods, pod1, pod2)
	return pods
}

func (ps *fakePodStore) Add(obj interface{}) error {
	return nil
}

func (ps *fakePodStore) Update(obj interface{}) error {
	return nil
}

func (ps *fakePodStore) Delete(obj interface{}) error {
	return nil
}

func (ps *fakePodStore) ListKeys() []string {
	return nil
}

func (ps *fakePodStore) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, false, nil
}

func (ps *fakePodStore) GetByKey(key string) (item interface{}, exists bool, err error) {
	return nil, false, nil
}

func (ps *fakePodStore) Replace(i []interface{}, s string) error {
	return nil
}

func (ps *fakePodStore) Resync() error {
	return nil
}

type fakePodStoreGetter struct {
	ps *fakePodStore
}

func (psg *fakePodStoreGetter) GetStore(name string) cache.Store {
	return psg.ps
}

var (
	config1 EgressPolicyConfig
	config2 EgressPolicyConfig

	pod1IP1 = slimcorev1.PodIP{IP: "1.2.3.4"}
	pod1IP2 = slimcorev1.PodIP{IP: "5.6.7.8"}

	pod1 = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "ns1",
			Labels:    map[string]string{"test": "foo"},
		},
		Spec: slimcorev1.PodSpec{},
		Status: slimcorev1.PodStatus{
			PodIP:  pod1IP1.IP,
			PodIPs: []slimcorev1.PodIP{pod1IP1, pod1IP2},
		},
	}
	pod1ID = types.NamespacedName{
		Name:      pod1.Name,
		Namespace: pod1.Namespace,
	}
	pod2IP1 = slimcorev1.PodIP{IP: "5.6.7.9"}
	pod2IP2 = slimcorev1.PodIP{IP: "5.6.7.10"}
	pod2    = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "pod-2",
			Namespace: "ns1",
			Labels:    map[string]string{"test": "bar"},
		},
		Spec: slimcorev1.PodSpec{},
		Status: slimcorev1.PodStatus{
			PodIP:  pod2IP1.IP,
			PodIPs: []slimcorev1.PodIP{pod2IP1, pod2IP2},
		},
	}
	pod2ID = types.NamespacedName{
		Name:      pod2.Name,
		Namespace: pod2.Namespace,
	}

	egressIP1 = net.ParseIP("192.168.33.11")
)

func (m *ManagerSuite) SetUpTest(c *C) {
	m.epm = NewEgressPolicyManager()

	var selectors []api.EndpointSelector
	selectors = append(selectors, api.EndpointSelector{
		LabelSelector: &slim_metav1.LabelSelector{
			MatchLabels: map[string]string{
				"test": "foo",
			},
		},
	})
	config1 = EgressPolicyConfig{
		id: types.NamespacedName{
			Name:      "test-foo",
			Namespace: "ns1",
		},
		endpointSelectors: selectors,
		egressIP:          egressIP1,
	}

	config2 = EgressPolicyConfig{
		id: types.NamespacedName{
			Name:      "test-bar",
			Namespace: "ns1",
		},
		endpointSelectors: selectors,
		egressIP:          egressIP1,
	}
}

// Tests if duplicate config with same egressIP is not added
func (m *ManagerSuite) TestManager_AddPolicy_DupEgressIP(c *C) {

	added, err := m.epm.AddEgressPolicy(config1)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	added, err = m.epm.AddEgressPolicy(config2)
	c.Assert(added, Equals, false)
	c.Assert(err, NotNil)
}

// Tests add policy, add pod, delete pod and then delete policy
func (m *ManagerSuite) TestManager_SimpleConfigMatching(c *C) {
	m.epm.RegisterGetStores(&fakePodStoreGetter{ps: &fakePodStore{}})

	// Add a policy.
	added, err := m.epm.AddEgressPolicy(config1)

	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(len(m.epm.policyConfigs), Equals, 1)
	c.Assert(m.epm.policyConfigs[config1.id].id.Name, Equals, config1.id.Name)
	c.Assert(m.epm.policyConfigs[config1.id].id.Namespace, Equals, config1.id.Namespace)
	c.Assert(len(m.epm.policyPods), Equals, 1)
	c.Assert(len(m.epm.policyPods[pod1ID]), Equals, 1)
	c.Assert(m.epm.policyPods[pod1ID][0], Equals, config1.id)

	// Add a pod.
	pod3 := pod2.DeepCopy()
	pod3.Labels["test"] = "foo"
	pod3ID := pod2ID

	m.epm.OnAddPod(pod3)

	c.Assert(len(m.epm.policyPods), Equals, 2)
	c.Assert(len(m.epm.policyPods[pod3ID]), Equals, 1)
	c.Assert(m.epm.policyPods[pod1ID][0], Equals, config1.id)

	// Delete the pod.
	m.epm.OnDeletePod(pod3)

	c.Assert(len(m.epm.policyPods), Equals, 1)
	_, found := m.epm.policyPods[pod3ID]
	c.Assert(found, Equals, false)

	// Delete policy.
	err = m.epm.DeleteEgressPolicy(config1)

	c.Assert(err, IsNil)
	c.Assert(len(m.epm.policyPods), Equals, 0)
	c.Assert(len(m.epm.policyConfigs), Equals, 0)
}
