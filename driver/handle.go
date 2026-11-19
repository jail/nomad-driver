// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: MPL-2.0 AND BSD-2-Clause

//go:build freebsd

package driver

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/plugins/drivers"
)

// taskHandle is the driver's record of a running task: the executor supervising
// its process, and its jail.
type taskHandle struct {
	// stateLock guards everything below it.
	stateLock sync.RWMutex

	logger       hclog.Logger
	exec         executor.Executor
	pluginClient *plugin.Client
	taskConfig   *drivers.TaskConfig
	procState    drivers.TaskState
	startedAt    time.Time
	completedAt  time.Time
	exitResult   *drivers.ExitResult

	// pid is that of the jexec(8) that became the task.
	pid int

	// jail is what the driver created for the task, and is shared with the
	// state in the task handle.
	jail *jailState
}

func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	attrs := map[string]string{
		"pid":  strconv.Itoa(h.pid),
		"jail": h.jail.Name,
		"jid":  strconv.Itoa(h.jail.JID),
		"root": h.jail.Root,
	}
	if h.jail.IP != "" {
		attrs["ip"] = h.jail.IP
	}
	if h.jail.Epair != "" {
		attrs["epair"] = h.jail.Epair
	}

	return &drivers.TaskStatus{
		ID:               h.taskConfig.ID,
		Name:             h.taskConfig.Name,
		State:            h.procState,
		StartedAt:        h.startedAt,
		CompletedAt:      h.completedAt,
		ExitResult:       h.exitResult,
		DriverAttributes: attrs,
	}
}

func (h *taskHandle) IsRunning() bool {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()
	return h.procState == drivers.TaskStateRunning
}

// jexecPrefix is the command prefix that runs something in this task's jail;
// see jexecCommand.
func (h *taskHandle) jexecPrefix() []string {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	prefix := []string{pathJexec}
	if h.taskConfig.User != "" {
		prefix = append(prefix, "-U", h.taskConfig.User)
	}
	return append(prefix, h.jail.Name)
}

// jailSnapshot returns a copy of the jail state for a caller that will write to
// it, as teardown does.  The slices are shared; nothing appends to them once
// the task has started.
func (h *taskHandle) jailSnapshot() *jailState {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	snapshot := *h.jail
	return &snapshot
}

// run waits for the task's process and records how it ended.
func (h *taskHandle) run() {
	h.stateLock.Lock()
	if h.exitResult == nil {
		h.exitResult = &drivers.ExitResult{}
	}
	h.stateLock.Unlock()

	ps, err := h.exec.Wait(context.Background())

	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	if err != nil {
		h.exitResult.Err = err
		h.procState = drivers.TaskStateUnknown
		h.completedAt = time.Now()
		return
	}
	h.procState = drivers.TaskStateExited
	h.exitResult.ExitCode = ps.ExitCode
	h.exitResult.Signal = ps.Signal
	h.completedAt = ps.Time
}
