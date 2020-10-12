// Copyright 2018 Authors of Cilium
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

package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egress"

	"github.com/spf13/cobra"
)

const (
	egressUpdateUsage = "Update endpoint IPs and their gateway (for debugging purpose).\n"
)

var bpfEgressUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update endpoint IPs and their gateways",
	Long:  egressListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress update <src_ip> <gw_ip>")

		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "requires 2 args\n")
			os.Exit(1)
		}

		key := egress.NewKey(net.ParseIP(args[0]))
		value := &egress.RemoteEndpointInfo{}

		if ip4 := net.ParseIP(args[1]).To4(); ip4 != nil {
			copy(value.TunnelEndpoint[:], ip4)
		}

		if err := egress.Egress.Update(&key, value); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressUpdateCmd)
}
