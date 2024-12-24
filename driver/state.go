// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause AND MPL-2.0

//go:build freebsd

package driver

import (
	"sync"
	"time"

	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/structs"
)

// TaskState is what the driver encodes into the task handle: everything
// RecoverTask needs to take a running task back over.
type TaskState struct {
	ReattachConfig *structs.ReattachConfig
	TaskConfig     *drivers.TaskConfig
	StartedAt      time.Time

	// Pid is the process ID of the jexec(8) that became the task.
	Pid int

	// Jail is what the driver created for the task.
	Jail *jailState
}

// taskStore maps task IDs to the driver's handles for them.
type taskStore struct {
	store map[string]*taskHandle
	lock  sync.RWMutex
}

func newTaskStore() *taskStore {
	return &taskStore{store: map[string]*taskHandle{}}
}

func (ts *taskStore) Set(id string, handle *taskHandle) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	ts.store[id] = handle
}

func (ts *taskStore) Get(id string) (*taskHandle, bool) {
	ts.lock.RLock()
	defer ts.lock.RUnlock()
	t, ok := ts.store[id]
	return t, ok
}

func (ts *taskStore) Delete(id string) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	delete(ts.store, id)
}
