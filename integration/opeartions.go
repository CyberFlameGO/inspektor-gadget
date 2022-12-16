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

package integration

import (
	"testing"
	"time"
)

type Operation interface {
	// Run runs the operation and wait its completion.
	Run(t *testing.T)

	// Start starts the operation and immediately returns, it does wait until
	// its completion, use Stop() for that.
	Start(t *testing.T)

	// Stop stops the operation and waits its completion.
	Stop(t *testing.T)

	// IsCleanup returns true if the operation is used to clean resource and
	// should not be skipped even if previous commands failed.
	IsCleanup() bool

	// IsStartAndStop returns true if the operation should first be started then
	// stopped after some time.
	IsStartAndStop() bool

	// Running returns true if the operation has been started.
	Running() bool
}

// RunOperations is used to run a list of commands with stopping/clean up logic.
func RunOperations[O Operation](ops []O, t *testing.T) {
	// Defer all cleanup commands so we are sure to exit clean whatever
	// happened
	defer func() {
		for _, o := range ops {
			if o.IsCleanup() {
				o.Run(t)
			}
		}
	}()

	// Defer stopping commands
	defer func() {
		for _, cmd := range ops {
			if cmd.IsStartAndStop() && cmd.Running() {
				// Wait a bit before stopping the command.
				time.Sleep(10 * time.Second)
				cmd.Stop(t)
			}
		}
	}()

	// Run all operations except cleanup ones
	for _, cmd := range ops {
		if cmd.IsCleanup() {
			continue
		}

		if cmd.IsStartAndStop() {
			cmd.Start(t)
			continue
		}

		cmd.Run(t)
	}
}
