// Copyright 2019-2022 The Inspektor Gadget authors
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

package trace

import (
	"encoding/json"
	"fmt"
	"os"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"

	"github.com/spf13/cobra"
)

type TraceEvent interface {
	any
}

// TraceParser defines the interface that every trace-gadget parser has to
// implement.
type TraceParser[Event TraceEvent] interface {
	// TransformEvent is called to transform an event to the requested output
	// format.
	TransformEvent(event *Event) string

	// BuildColumnsHeader returns a header with the requested custom columns
	// that exist in the predefined columns list. The columns are separated by
	// the predefined width.
	BuildColumnsHeader() string
}

// TraceGadget represents a gadget belonging to the trace category.
type TraceGadget[Event TraceEvent] struct {
	name        string
	commonFlags *utils.CommonFlags
	params      map[string]string
	parser      TraceParser[Event]
}

// Run runs a TraceGadget and prints the output after parsing it using the
// TraceParser's methods.
func (g *TraceGadget[Event]) Run() error {
	config := &utils.TraceConfig{
		GadgetName:       g.name,
		Operation:        "start",
		TraceOutputMode:  "Stream",
		TraceOutputState: "Started",
		CommonFlags:      g.commonFlags,
		Parameters:       g.params,
	}

	// Print header
	switch g.commonFlags.OutputMode {
	case commonutils.OutputModeJSON:
		// Nothing to print
	case commonutils.OutputModeColumns:
		fallthrough
	case commonutils.OutputModeCustomColumns:
		fmt.Println(g.parser.BuildColumnsHeader())
	}

	transformEvent := func(line string) string {
		var e Event

		if err := json.Unmarshal([]byte(line), &e); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
			return ""
		}

		return g.parser.TransformEvent(&e)
	}

	if err := utils.RunTraceAndPrintStream(config, transformEvent); err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	return nil
}

func NewTraceCmd() *cobra.Command {
	traceCmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace and print system events",
	}

	traceCmd.AddCommand(newBindCmd())
	traceCmd.AddCommand(newCapabilitiesCmd())
	traceCmd.AddCommand(newDNSCmd())
	traceCmd.AddCommand(newExecCmd())
	traceCmd.AddCommand(newFsSlowerCmd())
	traceCmd.AddCommand(newMountCmd())
	traceCmd.AddCommand(newNetworkCmd())
	traceCmd.AddCommand(newOOMKillCmd())
	traceCmd.AddCommand(newOpenCmd())
	traceCmd.AddCommand(newSignalCmd())
	traceCmd.AddCommand(newSNICmd())
	traceCmd.AddCommand(newTCPCmd())
	traceCmd.AddCommand(newTcpconnectCmd())

	return traceCmd
}
