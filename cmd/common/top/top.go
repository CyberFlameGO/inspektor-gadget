// Copyright 2022 The Inspektor Gadget authors
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

package top

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type TopEvent interface {
	any

	// TODO: The Go compiler does not support accessing a struct field x.f where
	// x is of type parameter type even if all types in the type parameter's
	// type set have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() *eventtypes.Event
}

type StatsPrinter interface {
	PrintStats()
}

// TopParser defines the interface that every top-gadget parser has to
// implement.
type TopParser[Stats any] interface {
	// BuildColumnsHeader returns a header to be used when the user requests to
	// present the output in columns.
	BuildColumnsHeader() string
	TransformIntoColumns(*Stats) string
}

type CommonTopFlags struct {
	OutputInterval int
	MaxRows        int
	SortBy         string
	ParsedSortBy   []string
}

type TopGadget[Stats any] struct {
	Name           string
	CommonTopFlags *CommonTopFlags
	OutputConfig   *commonutils.OutputConfig
	Parser         TopParser[Stats]
	ColMap         columns.ColumnMap[Stats]

	Printer StatsPrinter
}

func (g *TopGadget[Stats]) StartPrintLoop() {
	go func() {
		ticker := time.NewTicker(time.Duration(g.CommonTopFlags.OutputInterval) * time.Second)
		g.PrintHeader()
		for {
			<-ticker.C
			g.PrintHeader()
			g.Printer.PrintStats()
		}
	}()
}

func (g *TopGadget[Stats]) PrintHeader() {
	if g.OutputConfig.OutputMode == commonutils.OutputModeJSON {
		return
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		commonutils.ClearScreen()
	} else {
		fmt.Println("")
	}

	fmt.Println(g.Parser.BuildColumnsHeader())
}

func NewCommonTopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "top",
		Short: "Gather, sort and periodically report events according to a given criteria",
	}
}
