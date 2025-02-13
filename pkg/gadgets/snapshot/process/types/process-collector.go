// Copyright 2022-2023 The Inspektor Gadget authors
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

package types

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	ShowThreadsParam = "show-threads"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Command   string `json:"comm" column:"comm,template:comm"`
	Pid       int    `json:"pid" column:"pid,template:pid"`
	Tid       int    `json:"tid" column:"tid,template:pid,hide"`
	ParentPid int    `json:"ppid" column:"ppid,template:pid,hide"`
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}
