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

package cri

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// CRIClient implements the ContainerRuntimeClient interface using the CRI
// plugin interface to communicate with the different container runtimes.
type CRIClient struct {
	Name        string
	SocketPath  string
	ConnTimeout time.Duration

	conn   *grpc.ClientConn
	client pb.RuntimeServiceClient
}

func NewCRIClient(name, socketPath string, timeout time.Duration) (CRIClient, error) {
	conn, err := grpc.Dial(
		socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		return CRIClient{}, err
	}

	return CRIClient{
		Name:        name,
		SocketPath:  socketPath,
		ConnTimeout: timeout,
		conn:        conn,
		client:      pb.NewRuntimeServiceClient(conn),
	}, nil
}

func listContainers(c *CRIClient, filter *pb.ContainerFilter) ([]*pb.Container, error) {
	request := &pb.ListContainersRequest{}
	if filter != nil {
		request.Filter = filter
	}

	res, err := c.client.ListContainers(context.Background(), request)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers with request %+v: %w",
			request, err)
	}

	return res.GetContainers(), nil
}

func (c *CRIClient) GetContainers(options ...runtimeclient.Option) ([]*runtimeclient.ContainerData, error) {
	opts := runtimeclient.ParseOptions(options...)

	containers, err := listContainers(c, nil)
	if err != nil {
		return nil, err
	}

	ret := make([]*runtimeclient.ContainerData, 0)

	for _, container := range containers {
		if !opts.MatchRequestedState(containerStatusStateToRuntimeClientState(container.GetState())) {
			log.Debugf("CRIClient: container %q is not in expected state. Skipping it.", container.Id)
			continue
		}

		if !opts.MustIncludeDetails() {
			ret = append(ret, CRIContainerToContainerData(c.Name, container))
			continue
		}

		detailedContainer, err := c.getContainerDetails(container.Id, opts)
		if err != nil {
			log.Warnf("CRIClient: couldn't get container details for %q. Skipping it: %s",
				container.Id, err)
			continue
		}
		if detailedContainer.Details == nil {
			log.Warnf("CRIClient: container %q doesn't have details. Skipping it.", container.Id)
			continue
		}
		ret = append(ret, detailedContainer)
	}

	return ret, nil
}

func (c *CRIClient) GetContainer(containerID string, options ...runtimeclient.Option) (*runtimeclient.ContainerData, error) {
	opts := runtimeclient.ParseOptions(options...)

	containerID, err := runtimeclient.ParseContainerID(c.Name, containerID)
	if err != nil {
		return nil, err
	}

	if opts.MustIncludeDetails() {
		detailedContainer, err := c.getContainerDetails(containerID, opts)
		if err != nil {
			return nil, err
		}

		return detailedContainer, nil
	}

	containers, err := listContainers(c, &pb.ContainerFilter{
		Id: containerID,
		// TODO: Use the state from opts
		// State: &pb.ContainerStateValue{
		// 	State: runtimeStateToDockerState(opts.State()),
		// },
	})
	if err != nil {
		return nil, err
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("container %q not found", containerID)
	}
	if len(containers) > 1 {
		log.Warnf("CRIClient: multiple containers (%d) with ID %q. Taking the first one: %+v",
			len(containers), containerID, containers)
	}

	if !opts.MatchRequestedState(containerStatusStateToRuntimeClientState(containers[0].State)) {
		return nil, fmt.Errorf("container %q is not in expected state", containerID)
	}

	return CRIContainerToContainerData(c.Name, containers[0]), nil
}

func (c *CRIClient) getContainerDetails(containerID string, opts *runtimeclient.ContainerOptions) (*runtimeclient.ContainerData, error) {
	request := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	res, err := c.client.ContainerStatus(context.Background(), request)
	if err != nil {
		return nil, err
	}

	if !opts.MatchRequestedState(containerStatusStateToRuntimeClientState(res.Status.GetState())) {
		return nil, fmt.Errorf("container %q is not in the expected state", containerID)
	}

	return parseContainerDetailsData(c.Name, res.Status, res.Info)
}

func (c *CRIClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

// parseContainerDetailsData parses the container status and extra information
// returned by ContainerStatus() into a ContainerData structure.
func parseContainerDetailsData(
	runtimeName string,
	containerStatus *pb.ContainerStatus,
	extraInfo map[string]string,
) (*runtimeclient.ContainerData, error) {
	// Create container structure to be filled.
	containerData := &runtimeclient.ContainerData{
		ID:      containerStatus.Id,
		Name:    strings.TrimPrefix(containerStatus.GetMetadata().Name, "/"),
		Runtime: runtimeName,
		Details: &runtimeclient.ContainerDetailsData{},
	}

	// Fill K8S information.
	runtimeclient.EnrichWithK8sMetadata(containerData, containerStatus.Labels)

	// Parse the extra info and fill the data.
	err := parseExtraInfo(extraInfo, containerData.Details)
	if err != nil {
		return nil, err
	}

	return containerData, nil
}

// parseExtraInfo parses the extra information returned by ContainerStatus()
// into a ContainerDetailsData structure. It keeps backward compatibility after
// the ContainerInfo format was modified in:
// cri-o v1.18.0: https://github.com/cri-o/cri-o/commit/be8e876cdabec4e055820502fed227aa44971ddc
// containerd v1.6.0-beta.1: https://github.com/containerd/containerd/commit/85b943eb47bc7abe53b9f9e3d953566ed0f65e6c
// NOTE: CRI-O does not have runtime spec prior to 1.18.0
func parseExtraInfo(extraInfo map[string]string,
	containerDetailsData *runtimeclient.ContainerDetailsData,
) error {
	// Define the info content (only required fields).
	type RuntimeSpecContent struct {
		Mounts []struct {
			Destination string `json:"destination"`
			Source      string `json:"source,omitempty"`
		} `json:"mounts,omitempty"`
		Linux *struct {
			CgroupsPath string `json:"cgroupsPath,omitempty"`
		} `json:"linux,omitempty" platform:"linux"`
	}
	type InfoContent struct {
		Pid         int                `json:"pid"`
		RuntimeSpec RuntimeSpecContent `json:"runtimeSpec"`
	}

	// Set invalid value to PID.
	pid := -1
	containerDetailsData.Pid = pid

	// Get the extra info from the map.
	var runtimeSpec *RuntimeSpecContent
	info, ok := extraInfo["info"]
	if ok {
		// Unmarshal the JSON to fields.
		var infoContent InfoContent
		err := json.Unmarshal([]byte(info), &infoContent)
		if err != nil {
			return fmt.Errorf("failed extracting pid from container status reply: %w", err)
		}

		// Set the PID value.
		pid = infoContent.Pid

		// Set the runtime spec pointer, to be copied below.
		runtimeSpec = &infoContent.RuntimeSpec

		// Legacy parsing.
	} else {
		// Extract the PID.
		pidStr, ok := extraInfo["pid"]
		if !ok {
			return fmt.Errorf("container status reply from runtime doesn't contain pid")
		}
		var err error
		pid, err = strconv.Atoi(pidStr)
		if err != nil {
			return fmt.Errorf("failed to parse pid %q: %w", pidStr, err)
		}

		// Extract the runtime spec (may not exist).
		runtimeSpecStr, ok := extraInfo["runtimeSpec"]
		if ok {
			// Unmarshal the JSON to fields.
			runtimeSpec = &RuntimeSpecContent{}
			err := json.Unmarshal([]byte(runtimeSpecStr), runtimeSpec)
			if err != nil {
				return fmt.Errorf("failed extracting runtime spec from container status reply: %w", err)
			}
		}
	}

	// Validate extracted fields.
	if pid == 0 {
		return fmt.Errorf("got zero pid")
	}

	// Set the PID value.
	containerDetailsData.Pid = pid

	// Copy the runtime spec fields.
	if runtimeSpec != nil {
		if runtimeSpec.Linux != nil {
			containerDetailsData.CgroupsPath = runtimeSpec.Linux.CgroupsPath
		}
		if len(runtimeSpec.Mounts) > 0 {
			containerDetailsData.Mounts = make([]runtimeclient.ContainerMountData, len(runtimeSpec.Mounts))
			for i, specMount := range runtimeSpec.Mounts {
				containerDetailsData.Mounts[i] = runtimeclient.ContainerMountData{
					Destination: specMount.Destination,
					Source:      specMount.Source,
				}
			}
		}
	}

	return nil
}

// Convert the state from container status to state of runtime client.
func containerStatusStateToRuntimeClientState(containerStatusState pb.ContainerState) (runtimeClientState string) {
	switch containerStatusState {
	case pb.ContainerState_CONTAINER_CREATED:
		runtimeClientState = runtimeclient.StateCreated
	case pb.ContainerState_CONTAINER_RUNNING:
		runtimeClientState = runtimeclient.StateRunning
	case pb.ContainerState_CONTAINER_EXITED:
		runtimeClientState = runtimeclient.StateExited
	case pb.ContainerState_CONTAINER_UNKNOWN:
		runtimeClientState = runtimeclient.StateUnknown
	default:
		runtimeClientState = runtimeclient.StateUnknown
	}
	return
}

func CRIContainerToContainerData(runtimeName string, container *pb.Container) *runtimeclient.ContainerData {
	containerData := &runtimeclient.ContainerData{
		ID:      container.Id,
		Name:    strings.TrimPrefix(container.GetMetadata().Name, "/"),
		Runtime: runtimeName,
	}

	// Fill K8S information.
	runtimeclient.EnrichWithK8sMetadata(containerData, container.Labels)

	return containerData
}
