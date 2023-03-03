// Copyright 2023 The Inspektor Gadget authors
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

package kubemanager

import (
	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamContainerName = "containername"
	ParamSelector      = "selector"
	ParamAllNamespaces = "all-namespaces"
	ParamPodName       = "podname"
	ParamNamespace     = "namespace"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type KubeManager struct {
	gadgetTracerManager *gadgettracermanager.GadgetTracerManager
}

func (k *KubeManager) SetGadgetTracerMgr(g *gadgettracermanager.GadgetTracerManager) {
	log.Infof("gadget tracermgr set in kubemanager")
	k.gadgetTracerManager = g
}

func (k *KubeManager) Name() string {
	return "KubeManager"
}

func (k *KubeManager) Description() string {
	return "KubeManager handles container/pod/namespace information using Container-Collection and GadgetTracerMgr"
}

func (k *KubeManager) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *KubeManager) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ParamContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
		},
		{
			Key:         ParamSelector,
			Alias:       "l",
			Description: "Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
		},
		{
			Key:         ParamPodName,
			Alias:       "p",
			Description: "Show only data from pods with that name",
		},
		{
			Key:          ParamAllNamespaces,
			Alias:        "A",
			Description:  "Show data from pods in all namespaces",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		},
		{
			Key:         ParamNamespace,
			Alias:       "n",
			Description: "Show only data from pods in a given namespace",
		},
	}
}

func (k *KubeManager) Dependencies() []string {
	return nil
}

func (k *KubeManager) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	// We need to be able to get MountNSID or NetNSID, and set ContainerInfo, so
	// check for that first
	_, canEnrichEventFromMountNs := gadget.EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadget.EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	// Secondly, we need to be able to inject the ebpf map onto the tracer
	gi, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}

	instance, err := gi.NewInstance()
	if err != nil {
		log.Warn("failed to create dummy instance")
		return false
	}
	_, isMountNsMapSetter := instance.(MountNsMapSetter)
	_, isAttacher := instance.(Attacher)

	log.Debugf("> canEnrichEvent: %v", canEnrichEvent)
	log.Debugf(" > canEnrichEventFromMountNs: %v", canEnrichEventFromMountNs)
	log.Debugf(" > canEnrichEventFromNetNs: %v", canEnrichEventFromNetNs)
	log.Debugf("> isMountNsMapSetter: %v", isMountNsMapSetter)
	log.Debugf("> isAttacher: %v", isAttacher)

	return (isMountNsMapSetter && canEnrichEvent) || isAttacher
}

func (k *KubeManager) Init(params *params.Params) error {
	return nil
}

func (k *KubeManager) Close() error {
	return nil
}

func (k *KubeManager) Instantiate(gadgetContext operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	_, canEnrichEventFromMountNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	traceInstance := &KubeManagerInstance{
		id:                 uuid.New().String(),
		manager:            k,
		enrichEvents:       canEnrichEvent,
		attachedContainers: make(map[*containercollection.Container]struct{}),
		params:             params,
		tracer:             gadgetInstance,
		gadgetCtx:          gadgetContext,
	}

	return traceInstance, nil
}

type KubeManagerInstance struct {
	id              string
	manager         *KubeManager
	enrichEvents    bool
	mountnsmap      *ebpf.Map
	subscriptionKey string

	attachedContainers map[*containercollection.Container]struct{}
	attacher           Attacher
	params             *params.Params
	tracer             any
	gadgetCtx          operators.GadgetContext
}

func (m *KubeManagerInstance) Name() string {
	return "KubeManagerInstance"
}

func (m *KubeManagerInstance) PreGadgetRun() error {
	log := m.gadgetCtx.Logger()

	containerSelector := containercollection.ContainerSelector{
		Namespace: m.params.Get(ParamNamespace).AsString(),
		Podname:   m.params.Get(ParamPodName).AsString(),
		Name:      m.params.Get(ParamContainerName).AsString(),
	}

	if setter, ok := m.tracer.(MountNsMapSetter); ok {
		m.manager.gadgetTracerManager.AddTracer(m.id, containerSelector)
		// Create mount namespace map to filter by containers
		mountnsmap, err := m.manager.gadgetTracerManager.TracerMountNsMap(m.id)
		if err != nil {
			return err
			// return commonutils.WrapInErrManagerCreateMountNsMap(err)
		}

		log.Debugf("set mountnsmap for gadget")
		setter.SetMountNsMap(mountnsmap)

		m.mountnsmap = mountnsmap
	}

	if attacher, ok := m.tracer.(Attacher); ok {
		m.attacher = attacher

		attachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.AttachContainer()")
			err := attacher.AttachContainer(container)
			if err != nil {
				log.Warnf("start tracing container %q: %s", container.Name, err)
				return
			}

			m.attachedContainers[container] = struct{}{}

			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				container.Name, container.Pid, container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.Detach()")
			err := attacher.DetachContainer(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", container.Name, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				container.Name, container.Pid, container.Mntns, container.Netns)
		}

		id := uuid.New()
		m.subscriptionKey = id.String()

		log.Debugf("add subscription")
		containers := m.manager.gadgetTracerManager.Subscribe(
			m.subscriptionKey,
			containerSelector,
			func(event containercollection.PubSubEvent) {
				log.Debugf("%s: %s", event.Type.String(), event.Container.ID)
				switch event.Type {
				case containercollection.EventTypeAddContainer:
					attachContainerFunc(event.Container)
				case containercollection.EventTypeRemoveContainer:
					detachContainerFunc(event.Container)
				}
			},
		)

		for _, container := range containers {
			attachContainerFunc(container)
		}
	}

	return nil
}

func (m *KubeManagerInstance) PostGadgetRun() error {
	if m.mountnsmap != nil {
		log.Debugf("calling RemoveMountNsMap()")
		m.manager.gadgetTracerManager.RemoveTracer(m.id)
	}
	if m.subscriptionKey != "" {
		log.Debugf("calling Unsubscribe()")
		m.manager.gadgetTracerManager.Unsubscribe(m.subscriptionKey)

		// emit detach for all remaining containers
		for container := range m.attachedContainers {
			m.attacher.DetachContainer(container)
		}
	}
	return nil
}

func (m *KubeManagerInstance) enrich(ev any) {
	if event, canEnrichEventFromMountNs := ev.(operators.ContainerInfoFromMountNSID); canEnrichEventFromMountNs {
		m.manager.gadgetTracerManager.ContainerCollection.EnrichEventByMntNs(event)
	}
	if event, canEnrichEventFromNetNs := ev.(operators.ContainerInfoFromNetNSID); canEnrichEventFromNetNs {
		m.manager.gadgetTracerManager.ContainerCollection.EnrichEventByNetNs(event)
	}
}

func (m *KubeManagerInstance) EnrichEvent(ev any) error {
	if !m.enrichEvents {
		return nil
	}
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&KubeManager{})
}
