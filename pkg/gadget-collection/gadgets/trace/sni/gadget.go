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

package snisnoop

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets"
	snitracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/sni/tracer"
	types "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/sni/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Trace struct {
	helpers gadgets.GadgetHelpers
	client  client.Client

	started bool

	tracer *snitracer.Tracer

	netnsHost uint64
}

type TraceFactory struct {
	gadgets.BaseFactory

	netnsHost uint64
}

func NewFactory() gadgets.TraceFactory {
	netnsHost, _ := containerutils.GetNetNs(os.Getpid())
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
		netnsHost:   netnsHost,
	}
}

func (f *TraceFactory) Description() string {
	return `The snisnoop gadget retrieves Server Name Indication (SNI) from TLS requests.`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		trace.helpers.Unsubscribe(genPubSubKey(name))
		trace.tracer.Close()
		trace.tracer = nil
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			client:    f.Client,
			helpers:   f.Helpers,
			netnsHost: f.netnsHost,
		}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start snisnoop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop snisnoop",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

type pubSubKey string

func genPubSubKey(name string) pubSubKey {
	return pubSubKey(fmt.Sprintf("gadget/snisnoop/%s", name))
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	var err error
	t.tracer, err = snitracer.NewTracer()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start sni tracer: %s", err)
		return
	}

	fillEvent := func(event *types.Event, key string) {
		event.KubernetesNode = trace.Spec.Node
		keyParts := strings.SplitN(key, "/", 2)
		if len(keyParts) == 2 {
			event.KubernetesNamespace = keyParts[0]
			event.KubernetesPodName = keyParts[1]
		} else if key != "host" {
			event.Type = eventtypes.ERR
			event.Message = fmt.Sprintf("unknown key %s", key)
		}
	}
	printMessage := func(key string, t eventtypes.EventType, message string) string {
		event := &types.Event{
			Event: eventtypes.Event{
				Type: t,
				CommonData: eventtypes.CommonData{
					KubernetesNode: trace.Spec.Node,
				},
				Message: message,
			},
		}

		fillEvent(event, key)

		b, err := json.Marshal(event)
		if err != nil {
			return fmt.Sprintf("error marshalling results: %s", err)
		}
		return string(b)
	}
	printEvent := func(key, name string) string {
		event := &types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				CommonData: eventtypes.CommonData{
					KubernetesNode: trace.Spec.Node,
				},
			},
			Name: name,
		}
		fillEvent(event, key)

		b, err := json.Marshal(event)
		if err != nil {
			return fmt.Sprintf("error marshalling results: %s", err)
		}
		return string(b)
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	newSNIRequestCallback := func(key string) func(event types.Event) {
		return func(event types.Event) {
			t.helpers.PublishEvent(
				traceName,
				printEvent(key, event.Name),
			)
		}
	}

	genKey := func(container *containercollection.Container) string {
		if container.Netns == t.netnsHost {
			return "host"
		}
		return container.KubernetesNamespace + "/" + container.KubernetesPodName
	}

	attachContainerFunc := func(container *containercollection.Container) error {
		key := genKey(container)

		err = t.tracer.Attach(key, container.Pid, newSNIRequestCallback(key))
		if err != nil {
			t.helpers.PublishEvent(
				traceName,
				printMessage(key, eventtypes.ERR, fmt.Sprintf("failed to attach tracer: %s", err)),
			)
			return err
		}
		t.helpers.PublishEvent(
			traceName,
			printMessage(key, eventtypes.DEBUG, "tracer attached"),
		)
		return nil
	}

	detachContainerFunc := func(container *containercollection.Container) {
		key := genKey(container)

		err := t.tracer.Detach(key)
		if err != nil {
			t.helpers.PublishEvent(
				traceName,
				printMessage(key, eventtypes.ERR, fmt.Sprintf("failed to detach tracer: %s", err)),
			)
			return
		}
		t.helpers.PublishEvent(
			traceName,
			printMessage(key, eventtypes.DEBUG, "tracer detached"),
		)
	}

	containerEventCallback := func(event containercollection.PubSubEvent) {
		switch event.Type {
		case containercollection.EventTypeAddContainer:
			attachContainerFunc(event.Container)
		case containercollection.EventTypeRemoveContainer:
			detachContainerFunc(event.Container)
		}
	}

	existingContainers := t.helpers.Subscribe(
		genPubSubKey(trace.ObjectMeta.Namespace+"/"+trace.ObjectMeta.Name),
		*gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		containerEventCallback,
	)

	for _, c := range existingContainers {
		err := attachContainerFunc(c)
		if err != nil {
			log.Warnf("Warning: couldn't attach BPF program: %s", err)
			break
		}
	}
	t.started = true

	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.helpers.Unsubscribe(genPubSubKey(trace.ObjectMeta.Namespace + "/" + trace.ObjectMeta.Name))
	t.tracer.Close()
	t.tracer = nil
	t.started = false

	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}
