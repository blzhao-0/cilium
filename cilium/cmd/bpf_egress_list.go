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
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egress"

	"github.com/spf13/cobra"
)

const (
	egressListUsage = "List endpoint IPs and their gateway.\n"
)

var bpfEgressListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List endpoint IPs and their gateways",
	Long:    egressListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress list")

		bpfEgressList := make(map[string][]string)
		if err := egress.Egress.Dump(bpfEgressList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfEgressList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
				os.Exit(1)
			}
			return
		}

		if len(bpfEgressList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n%v\n", kernelVersionWarning)
		} else {
			TablePrinter(ipAddrTitle, "Identity Key TunnelIP EgressIP", bpfEgressList)
		}
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressListCmd)
	command.AddJSONOutput(bpfEgressListCmd)
}
