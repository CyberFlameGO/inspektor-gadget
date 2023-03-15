// Copyright 2021-2023 The Inspektor Gadget authors
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
	"bufio"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	socketcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang iterTCPv4 ./bpf/tcp4-collector.c -- -I../../../../${TARGET} -Werror -O2 -g -c -x c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang iterUDPv4 ./bpf/udp4-collector.c -- -I../../../../${TARGET} -Werror -O2 -g -c -x c

func parseIPv4(ipU32 uint32) string {
	ipBytes := make([]byte, 4)

	// net.IP() expects network byte order and parseIPv4 receives an
	// argument in host byte order, so it needs to be converted first
	binary.BigEndian.PutUint32(ipBytes, ipU32)
	ip := net.IP(ipBytes)

	return ip.String()
}

// Format from socket_bpf_seq_print() in bpf/socket_common.h
func parseStatus(proto string, statusUint uint8) (string, error) {
	statusMap := [...]string{
		"ESTABLISHED", "SYN_SENT", "SYN_RECV",
		"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT",
		"LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV",
	}

	// Kernel enum starts from 1, adjust it to the statusMap
	if statusUint == 0 || len(statusMap) <= int(statusUint-1) {
		return "", fmt.Errorf("invalid %s status: %d", proto, statusUint)
	}
	status := statusMap[statusUint-1]

	// Transform TCP status into something more suitable for UDP
	if proto == "UDP" {
		switch status {
		case "ESTABLISHED":
			status = "ACTIVE"
		case "CLOSE":
			status = "INACTIVE"
		default:
			return "", fmt.Errorf("unexpected %s status %s", proto, status)
		}
	}

	return status, nil
}

func getTCPIter() (*link.Iter, error) {
	objs := iterTCPv4Objects{}
	if err := loadIterTCPv4Objects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load TCP BPF objects: %w", err)
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.IgSnapTcp4,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach TCP BPF iterator: %w", err)
	}

	return it, nil
}

func getUDPIter() (*link.Iter, error) {
	objs := iterUDPv4Objects{}
	if err := loadIterUDPv4Objects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load UDP BPF objects: %w", err)
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.IgSnapUdp4,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach UDP BPF iterator: %w", err)
	}

	return it, nil
}

func RunCollector(pid uint32, podname, namespace, node string, proto socketcollectortypes.Proto) ([]*socketcollectortypes.Event, error) {
	var err error
	var it *link.Iter
	iters := []*link.Iter{}

	defer func() {
		for _, it := range iters {
			it.Close()
		}
	}()

	if proto == socketcollectortypes.TCP || proto == socketcollectortypes.ALL {
		it, err = getTCPIter()
		if err != nil {
			return nil, err
		}
		iters = append(iters, it)
	}

	if proto == socketcollectortypes.UDP || proto == socketcollectortypes.ALL {
		it, err = getUDPIter()
		if err != nil {
			return nil, err
		}
		iters = append(iters, it)
	}

	sockets := []*socketcollectortypes.Event{}
	err = netnsenter.NetnsEnter(int(pid), func() error {
		for _, it := range iters {
			reader, err := it.Open()
			if err != nil {
				return fmt.Errorf("failed to open BPF iterator: %w", err)
			}
			defer reader.Close()

			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				var status, proto string
				var destp, srcp uint16
				var dest, src uint32
				var hexStatus uint8
				var inodeNumber uint64

				// Format from socket_bpf_seq_print() in bpf/socket_common.h
				// IP addresses and ports are in host-byte order
				len, err := fmt.Sscanf(scanner.Text(), "%s %08X %04X %08X %04X %02X %d",
					&proto, &src, &srcp, &dest, &destp, &hexStatus, &inodeNumber)
				if err != nil || len != 7 {
					return fmt.Errorf("failed to parse sockets information: %w", err)
				}

				status, err = parseStatus(proto, hexStatus)
				if err != nil {
					return err
				}

				// TODO: Receive the netns from caller
				netns, err := containerutils.GetNetNs(int(pid))
				if err != nil {
					return fmt.Errorf("getting netns for pid %d: %w", pid, err)
				}

				sockets = append(sockets, &socketcollectortypes.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
						// TODO: This can be removed as events will be enriched
						//  by the eventHandler
						CommonData: eventtypes.CommonData{
							Node:      node,
							Namespace: namespace,
							Pod:       podname,
						},
					},
					Protocol:      proto,
					LocalAddress:  parseIPv4(src),
					LocalPort:     srcp,
					RemoteAddress: parseIPv4(dest),
					RemotePort:    destp,
					Status:        status,
					InodeNumber:   inodeNumber,
					WithNetNsID:   eventtypes.WithNetNsID{NetNsID: netns},
				})
			}

			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed reading output of BPF iterator: %w", err)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return sockets, nil
}

// ---

type Tracer struct {
	// visitedNamespaces is a map where the key is the netns inode number and
	// the value is the pid of one of the containers that share that netns. Such
	// pid is used by NetnsEnter. TODO: Improve NetnsEnter to also work with the
	// netns directly.
	visitedNamespaces map[uint64]uint32
	protocols         string
	eventHandler      func([]*socketcollectortypes.Event)
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		visitedNamespaces: make(map[uint64]uint32),
	}
	return tracer, nil
}

func (t *Tracer) AttachContainer(container *containercollection.Container) error {
	if _, ok := t.visitedNamespaces[container.Netns]; ok {
		return nil
	}
	t.visitedNamespaces[container.Netns] = container.Pid
	return nil
}

func (t *Tracer) DetachContainer(container *containercollection.Container) error {
	return nil
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*socketcollectortypes.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventHandler = nh
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	t.protocols = gadgetCtx.GadgetParams().Get(ParamProto).AsString()

	allSockets := []*socketcollectortypes.Event{}

	for netns, pid := range t.visitedNamespaces {
		// TODO: Remove podname, namespace and node arguments from RunCollector.
		// The enrichment will be done in the event handler. In addition, pass
		// the netns to avoid retrieving it again in RunCollector.
		sockets, err := RunCollector(pid, "", "", "", socketcollectortypes.ProtocolsMap[t.protocols])
		if err != nil {
			return fmt.Errorf("snapshotting sockets in netns %d: %w", netns, err)
		}
		allSockets = append(allSockets, sockets...)
	}

	t.eventHandler(allSockets)
	return nil
}
