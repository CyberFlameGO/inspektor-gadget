// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type event_t snisnoop ./bpf/snisnoop.c -- $CLANG_OS_FLAGS -I./bpf/ -I../../../internal/socketenricher/bpf"

const (
	BPFProgName         = "ig_trace_sni"
	BPFPerfMapName      = "events"
	BPFSocketAttach     = 50
	TLSMaxServerNameLen = len(snisnoopEventT{}.Name)
)

type Tracer struct {
	*networktracer.Tracer[types.Event]
}

func NewTracer() (*Tracer, error) {
	spec, err := loadSnisnoop()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	networkTracer, err := networktracer.NewTracer(
		spec,
		BPFProgName,
		BPFPerfMapName,
		BPFSocketAttach,
		types.Base,
		parseSNIEvent,
	)
	if err != nil {
		return nil, fmt.Errorf("creating network tracer: %w", err)
	}

	return &Tracer{Tracer: networkTracer}, nil
}

func parseSNIEvent(sample []byte, netns uint64) (*types.Event, error) {
	bpfEvent := (*snisnoopEventT)(unsafe.Pointer(&sample[0]))
	if len(sample) < int(unsafe.Sizeof(*bpfEvent)) {
		return nil, errors.New("invalid sample size")
	}

	timestamp := gadgets.WallTimeFromBootTime(bpfEvent.Timestamp)

	name := gadgets.FromCString(bpfEvent.Name[:])
	if len(name) == 0 {
		return nil, nil
	}

	event := types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: timestamp,
		},
		Pid:           bpfEvent.Pid,
		Tid:           bpfEvent.Tid,
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MountNsId},
		WithNetNsID:   eventtypes.WithNetNsID{NetNsID: netns},
		Comm:          gadgets.FromCString(bpfEvent.Task[:]),

		Name: name,
	}

	return &event, nil
}

// --- Registry changes

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	// TODO: Clean up
	tracer, err := NewTracer()
	if err != nil {
		return err
	}
	t.Tracer = tracer.Tracer
	return nil
}
