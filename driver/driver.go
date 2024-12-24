// Copyright (c) HashiCorp, Inc.
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: MPL-2.0

//go:build freebsd

package driver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/consul-template/signals"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/allocdir"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/drivers/fsisolation"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	"github.com/hashicorp/nomad/plugins/shared/structs"
	"github.com/jail/nomad-driver/jail"
)

const (
	// pluginName is what a job's driver field has to match.
	pluginName = "jail"

	pluginVersion = "v0.1.0"

	fingerprintPeriod = 30 * time.Second

	// taskHandleVersion is the version of the state encoded into a task
	// handle.  Bump it when jailState changes shape.
	taskHandleVersion = 1
)

var (
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{drivers.ApiVersion010},
		PluginVersion:     pluginVersion,
		Name:              pluginName,
	}

	capabilities = &drivers.Capabilities{
		SendSignals: true,
		Exec:        true,

		// Nomad addresses the task's directories by their paths inside
		// the jail, and does not pass the host's environment through.
		FSIsolation: fsisolation.Image,

		NetIsolationModes: []drivers.NetIsolationMode{
			// ip4=inherit.
			drivers.NetIsolationModeHost,
			// vnet=new.
			drivers.NetIsolationModeTask,
			// ip4=disable.
			drivers.NetIsolationModeNone,
		},

		// FreeBSD has no CNI, so there is no group network to join or
		// create.
		MustInitiateNetwork: false,

		MountConfigs: drivers.MountConfigSupportAll,
	}
)

// Driver is a Nomad task driver that runs tasks in FreeBSD jails.
type Driver struct {
	// eventer fans task events out to every TaskEvents caller.
	eventer *eventer.Eventer

	config *Config

	// nomadConfig is the client's configuration, which launching the
	// executor needs.
	nomadConfig *base.ClientDriverConfig

	tasks *taskStore

	// ctx is cancelled when the driver shuts down.
	ctx context.Context

	signalShutdown context.CancelFunc

	logger hclog.Logger
}

// NewPlugin returns a new jail driver plugin.
func NewPlugin(logger hclog.Logger) drivers.DriverPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named(pluginName)

	return &Driver{
		eventer:        eventer.NewEventer(ctx, logger),
		config:         &Config{},
		tasks:          newTaskStore(),
		ctx:            ctx,
		signalShutdown: cancel,
		logger:         logger,
	}
}

// PluginInfo returns information describing the plugin.
func (d *Driver) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

// ConfigSchema returns the plugin configuration schema.
func (d *Driver) ConfigSchema() (*hclspec.Spec, error) {
	return configSpec, nil
}

// SetConfig is called by the client to pass the plugin's configuration.
func (d *Driver) SetConfig(cfg *base.Config) error {
	// Nomad applies configSpec's defaults to a config block that exists.
	// An agent that names the plugin without one sends nothing, so the
	// defaults are needed here too.
	config := Config{
		Enabled:            true,
		DefaultNetworkMode: NetworkInherit,
		ResourceLimits:     true,
		GC:                 GCConfig{Jail: true},
	}
	if len(cfg.PluginConfig) != 0 {
		config = Config{}
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return err
		}
		if config.DefaultNetworkMode == "" {
			config.DefaultNetworkMode = NetworkInherit
		}
	}
	if err := config.Validate(); err != nil {
		return err
	}
	d.config = &config

	if cfg.AgentConfig != nil {
		d.nomadConfig = cfg.AgentConfig.Driver
	}

	// A jail outlives the agent that made it, and Nomad only recovers the
	// allocations it still knows about.
	if d.config.Enabled && d.config.GC.Jail {
		d.reapOrphans()
	}

	return nil
}

// TaskConfigSchema returns the HCL schema of a task's configuration.
func (d *Driver) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}

// Capabilities returns the features the driver supports.
func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

// Fingerprint returns a channel of health and node attribute reports.
func (d *Driver) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint)
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

// handleFingerprint sends a fingerprint at once, as Nomad expects, and then one
// every fingerprintPeriod.
func (d *Driver) handleFingerprint(ctx context.Context, ch chan<- *drivers.Fingerprint) {
	defer close(ch)

	ticker := time.NewTimer(0)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			ticker.Reset(fingerprintPeriod)
			select {
			case ch <- d.buildFingerprint():
			case <-ctx.Done():
				return
			case <-d.ctx.Done():
				return
			}
		}
	}
}

// StartTask creates a jail for the task and starts its command in it.
//
// Whatever is created is recorded in the task's jailState as it goes, and torn
// down again if a later step fails.
func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	var taskConfig TaskConfig
	if err := cfg.DecodeDriverConfig(&taskConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config: %w", err)
	}
	if err := taskConfig.Validate(d.config); err != nil {
		return nil, nil, err
	}

	// A device reaches a Linux driver as a node to create in the container.
	// What appears in a jail's /dev is decided by its devfs(5) ruleset, so
	// there is nothing to translate one into.
	if len(cfg.Devices) > 0 {
		paths := make([]string, 0, len(cfg.Devices))
		for _, dev := range cfg.Devices {
			paths = append(paths, dev.TaskPath)
		}
		return nil, nil, fmt.Errorf("this driver cannot attach devices (%s) to a jail; "+
			"expose devices to a jail with a devfs.rules(5) ruleset and the task's "+
			"devfs_ruleset instead", strings.Join(paths, ", "))
	}

	mode := d.networkMode(cfg, &taskConfig)
	logger := d.logger.With("task_name", cfg.Name, "alloc_id", cfg.AllocID)
	logger.Info("starting task", "network_mode", mode, "command", taskConfig.Command)

	st := &jailState{Name: jailName(cfg)}

	// Roll back unless the end is reached.
	started := false
	defer func() {
		if !started {
			if err := d.teardown(logger, st); err != nil {
				logger.Error("could not clean up after a failed start", "error", err)
			}
		}
	}()

	// The name is derived from the allocation and task, so a jail that has
	// it is this task's, from an earlier run.
	if err := d.reclaimFor(logger, cfg, st.Name); err != nil {
		return nil, nil, err
	}

	if err := prepareRootfs(d.ctx, logger, cfg, &taskConfig, d.config, st); err != nil {
		return nil, nil, err
	}
	if err := checkRootNotInUse(st.Root); err != nil {
		return nil, nil, err
	}

	mounts, err := mountAll(st.Root, taskMounts(cfg, &taskConfig, mode), logger)
	st.Mounts = append(st.Mounts, mounts...)
	if err != nil {
		return nil, nil, err
	}

	if err := writeResolvConf(st.Root, cfg.DNS); err != nil {
		// An image with no /etc, or a read-only one, is fine; its DNS
		// is then its own business.
		logger.Warn("could not write resolv.conf into the jail", "error", err)
		d.emitEvent(cfg, "Could not write the task's DNS configuration into the jail: %v", err)
	}

	hostname := taskConfig.Hostname
	if hostname == "" {
		hostname = st.Name
	}
	params, err := jailParams(&taskConfig, st, mode, hostname)
	if err != nil {
		return nil, nil, err
	}
	// FlagCreate alone, so that a name collision is an error and not an
	// update of somebody else's jail.
	jid, err := jail.Set(jail.FlagCreate, params...)
	if err != nil {
		return nil, nil, fmt.Errorf("creating jail %s: %w", st.Name, err)
	}
	st.JID = jid
	logger.Debug("created jail", "jail", st.Name, "jid", jid, "root", st.Root)

	if err := d.configureNetwork(logger, &taskConfig, st, mode); err != nil {
		return nil, nil, err
	}

	if taskConfig.Cpuset {
		if err := applyCpuset(d.ctx, logger, jid, cfg.Resources); err != nil {
			return nil, nil, err
		}
	}
	if taskConfig.ResourceLimits && d.config.ResourceLimits {
		wanted := rctlRules(st, &taskConfig, cfg.Resources)
		rules, err := applyRCTL(d.ctx, logger, wanted, len(taskConfig.ExtraRCTL) > 0)
		st.RCTLRules = rules
		if err != nil {
			return nil, nil, err
		}
		if len(wanted) > 0 && len(rules) == 0 {
			d.emitEvent(cfg, "Resource limits are not being enforced: this kernel has "+
				"resource accounting disabled (kern.racct.enable)")
		}
	}

	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	exec, pluginClient, err := executor.CreateExecutor(
		logger.Named("executor"), d.nomadConfig, &executor.ExecutorConfig{
			LogFile:  filepath.Join(cfg.TaskDir().Dir, "executor.out"),
			LogLevel: "debug",
		})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create executor: %w", err)
	}
	// From here on a failure has to take the executor down too.
	defer func() {
		if !started {
			pluginClient.Kill()
		}
	}()

	command, args := jexecCommand(st.JID, cfg, &taskConfig, jexecSupportsWorkDir())
	ps, err := exec.Launch(&executor.ExecCommand{
		Cmd:        command,
		Args:       args,
		StdoutPath: cfg.StdoutPath,
		StderrPath: cfg.StderrPath,
		Env:        cfg.EnvList(),
		TaskDir:    cfg.TaskDir().Dir,
		Resources:  cfg.Resources,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to launch command with executor: %w", err)
	}

	h := &taskHandle{
		exec:         exec,
		pid:          ps.Pid,
		pluginClient: pluginClient,
		taskConfig:   cfg,
		procState:    drivers.TaskStateRunning,
		startedAt:    time.Now().Round(time.Millisecond),
		logger:       logger,
		jail:         st,
	}

	driverState := TaskState{
		ReattachConfig: structs.ReattachConfigFromGoPlugin(pluginClient.ReattachConfig()),
		Pid:            ps.Pid,
		TaskConfig:     cfg,
		StartedAt:      h.startedAt,
		Jail:           st,
	}
	if err := handle.SetDriverState(&driverState); err != nil {
		return nil, nil, fmt.Errorf("failed to set driver state: %w", err)
	}

	d.tasks.Set(cfg.ID, h)
	go h.run()

	started = true
	return handle, driverNetwork(st, mode), nil
}

// driverNetwork returns the address to register a task's services at.  Only a
// vnet task has one of its own; the others share the host's.
func driverNetwork(st *jailState, mode string) *drivers.DriverNetwork {
	if mode != NetworkVnet || st.IP == "" {
		return nil
	}
	return &drivers.DriverNetwork{
		IP:            st.IP,
		AutoAdvertise: true,
	}
}

// networkMode picks a task's network mode: the job's, else what Nomad's network
// isolation implies, else the operator's default.
func (d *Driver) networkMode(cfg *drivers.TaskConfig, tc *TaskConfig) string {
	if tc.NetworkMode != "" {
		return tc.NetworkMode
	}
	if cfg.NetworkIsolation != nil {
		switch cfg.NetworkIsolation.Mode {
		case drivers.NetIsolationModeNone:
			return NetworkNone
		case drivers.NetIsolationModeHost:
			return NetworkInherit
		}
	}
	return d.config.DefaultNetworkMode
}

// configureNetwork does the part of a task's networking that needs the jail to
// exist.
func (d *Driver) configureNetwork(logger hclog.Logger, tc *TaskConfig, st *jailState, mode string) error {
	switch mode {
	case NetworkAlias:
		aliases, err := configureAliases(d.ctx, logger, tc)
		st.Aliases = aliases
		return err
	case NetworkVnet:
		return createVnet(d.ctx, logger, st.JID, bridgeFor(d.config, tc.Vnet), tc.Vnet, st)
	}
	return nil
}

// RecoverTask rebuilds the driver's state for a task after a restart.
func (d *Driver) RecoverTask(handle *drivers.TaskHandle) error {
	if handle == nil {
		return errors.New("error: handle cannot be nil")
	}
	if _, ok := d.tasks.Get(handle.Config.ID); ok {
		return nil
	}

	var taskState TaskState
	if err := handle.GetDriverState(&taskState); err != nil {
		return fmt.Errorf("failed to decode task state from handle: %w", err)
	}
	st := taskState.Jail
	if st == nil {
		return errors.New("task handle has no jail state")
	}
	logger := d.logger.With("task_name", handle.Config.Name, "alloc_id", handle.Config.AllocID)

	// A jail does not survive a reboot and the kernel reassigns jail IDs,
	// so the ID in the handle is checked against the jail's name.
	switch info, err := jail.Inspect(st.Name); {
	case err == nil:
		if info.JID != st.JID {
			logger.Info("jail ID changed since the task was started",
				"jail", st.Name, "old_jid", st.JID, "jid", info.JID)
			st.JID = info.JID
		}
	case errors.Is(err, jail.ErrNotFound):
		// With the jail gone the task is not running, whatever the
		// executor says.  Clean up and fail, which makes Nomad restart
		// it.
		logger.Warn("jail is gone, cannot recover the task", "jail", st.Name)
		if err := d.teardown(logger, st); err != nil {
			logger.Error("could not clean up after a vanished jail", "error", err)
		}
		return fmt.Errorf("jail %s no longer exists", st.Name)
	default:
		return fmt.Errorf("looking for jail %s: %w", st.Name, err)
	}

	plugRC, err := structs.ReattachConfigToGoPlugin(taskState.ReattachConfig)
	if err != nil {
		return fmt.Errorf("failed to build ReattachConfig from task state: %w", err)
	}
	execImpl, pluginClient, err := executor.ReattachToExecutor(plugRC,
		logger.Named("executor"), d.nomadConfig.Topology.Compute())
	if err != nil {
		return fmt.Errorf("failed to reattach to executor: %w", err)
	}

	h := &taskHandle{
		exec:         execImpl,
		pid:          taskState.Pid,
		pluginClient: pluginClient,
		taskConfig:   taskState.TaskConfig,
		procState:    drivers.TaskStateRunning,
		startedAt:    taskState.StartedAt,
		exitResult:   &drivers.ExitResult{},
		logger:       logger,
		jail:         st,
	}

	d.tasks.Set(taskState.TaskConfig.ID, h)
	go h.run()

	logger.Info("recovered task", "jail", st.Name, "jid", st.JID)
	return nil
}

// WaitTask returns a channel Nomad uses to learn that a task exited.
func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	ch := make(chan *drivers.ExitResult)
	go d.handleWait(ctx, handle, ch)
	return ch, nil
}

func (d *Driver) handleWait(ctx context.Context, handle *taskHandle, ch chan *drivers.ExitResult) {
	defer close(ch)

	var result *drivers.ExitResult
	ps, err := handle.exec.Wait(ctx)
	if err != nil {
		result = &drivers.ExitResult{
			Err: fmt.Errorf("executor: error waiting on process: %w", err),
		}
	} else {
		result = &drivers.ExitResult{
			ExitCode: ps.ExitCode,
			Signal:   ps.Signal,
		}
	}

	select {
	case <-ctx.Done():
	case <-d.ctx.Done():
	case ch <- result:
	}
}

// StopTask signals a task's process and waits for it, killing it after the
// timeout.
func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	// The executor supervises the jexec(8) that became the task, so this
	// signals the task itself.  Whatever else it forked dies with the jail,
	// in DestroyTask.
	if err := handle.exec.Shutdown(signal, timeout); err != nil {
		if handle.pluginClient.Exited() {
			return nil
		}
		return fmt.Errorf("executor Shutdown failed: %w", err)
	}
	return nil
}

// DestroyTask removes a task's jail and everything the driver created for it.
func (d *Driver) DestroyTask(taskID string, force bool) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}
	if handle.IsRunning() && !force {
		return errors.New("cannot destroy running task")
	}

	if !handle.pluginClient.Exited() {
		if err := handle.exec.Shutdown("", 0); err != nil {
			handle.logger.Error("destroying executor failed", "error", err)
		}
		handle.pluginClient.Kill()
	}

	// teardown writes to the state it is given, and the handle's may still
	// be read by an InspectTask in flight.
	err := d.teardown(handle.logger, handle.jailSnapshot())
	d.tasks.Delete(taskID)
	return err
}

// teardown undoes what StartTask created, in reverse, and keeps going past a
// failure.  It is safe to call more than once, and at any point during a start.
func (d *Driver) teardown(logger hclog.Logger, st *jailState) error {
	if st == nil {
		return nil
	}
	var errs []error

	// First, because a rule that outlived its jail would apply to the next
	// jail of the same name.
	if err := removeRCTL(d.ctx, logger, st); err != nil {
		errs = append(errs, err)
	}
	st.RCTLRules = nil

	// Removing the jail kills its processes, which is what frees its
	// filesystems.
	if st.JID != 0 {
		if err := jail.Remove(st.JID); err != nil && !errors.Is(err, jail.ErrNotFound) {
			errs = append(errs, fmt.Errorf("removing jail %s: %w", st.Name, err))
		} else {
			st.JID = 0
		}
	}

	if err := destroyEpair(d.ctx, logger, st); err != nil {
		errs = append(errs, err)
	}
	st.Epair, st.Bridge = "", ""

	if err := removeAliases(d.ctx, logger, st.Aliases); err != nil {
		errs = append(errs, err)
	}
	st.Aliases = nil

	if err := unmountAll(st); err != nil {
		errs = append(errs, err)
	}
	st.Mounts = nil

	if err := destroyDataset(d.ctx, logger, st.Dataset); err != nil {
		errs = append(errs, err)
	} else {
		st.Dataset = ""
	}

	return errors.Join(errs...)
}

// reclaim removes a jail left behind by an earlier run of the same task, with
// its mounts.
func (d *Driver) reclaim(logger hclog.Logger, name string) error {
	info, err := jail.Inspect(name)
	switch {
	case errors.Is(err, jail.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("looking for an existing jail named %s: %w", name, err)
	}

	logger.Warn("reclaiming a jail left behind by an earlier run", "jail", name, "jid", info.JID)
	return d.teardown(logger, d.reclaimState(info))
}

// reclaimFor is reclaim, with a task event to say so.
func (d *Driver) reclaimFor(logger hclog.Logger, cfg *drivers.TaskConfig, name string) error {
	exists, _, err := jail.Exists(name)
	if err != nil {
		return fmt.Errorf("looking for an existing jail named %s: %w", name, err)
	}
	if !exists {
		return nil
	}
	d.emitEvent(cfg, "Reclaiming the jail %s, left behind by an earlier run of this task", name)
	return d.reclaim(logger, name)
}

// reclaimState rebuilds enough of a jail's state to tear it down, for a jail
// found on the system rather than in a task handle.
//
// Its mounts follow from its root.  The aliases of an alias-mode task cannot be
// rebuilt, and are left.
func (d *Driver) reclaimState(info jail.Info) *jailState {
	st := &jailState{Name: info.Name, JID: info.JID, Root: info.Path}

	if filepath.Base(info.Path) == rootfsMountDir {
		// The driver mounted the root, so all of it is the task's.
		st.Mounts = []string{info.Path}
	} else {
		// The job named the root, so only the driver's own mount points
		// go.
		st.Mounts = driverMountPoints(info.Path)
	}

	if d.config.ZFSParent != "" {
		dataset := d.config.ZFSParent + "/" + info.Name
		if exists, err := datasetExists(d.ctx, d.logger, dataset); err == nil && exists {
			st.Dataset = dataset
		}
	}
	return st
}

// reapOrphans removes the driver's jails that no task is coming back for.
//
// It runs when the driver is configured, before any RecoverTask, so it cannot
// go by what the driver knows.  It goes by the allocation directory, which
// Nomad keeps for as long as it means to recover the allocation.
func (d *Driver) reapOrphans() {
	jails, err := jail.List()
	if err != nil {
		d.logger.Warn("could not list jails to reap orphans", "error", err)
		return
	}

	for _, info := range jails {
		if !isDriverJail(info.Name) || info.Path == "" {
			continue
		}
		reason, orphan := orphanReason(info.Path)
		if !orphan {
			continue
		}
		d.logger.Warn("reaping an orphaned jail", "jail", info.Name, "jid", info.JID,
			"root", info.Path, "reason", reason)
		if err := d.teardown(d.logger, d.reclaimState(info)); err != nil {
			d.logger.Error("could not reap jail", "jail", info.Name, "error", err)
		}
	}
}

// orphanReason reports whether the jail rooted at root belongs to an allocation
// that is gone, and why: its root has gone, or the allocation directory behind
// its /alloc has.
func orphanReason(root string) (string, bool) {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return "its root directory is gone", true
	}

	allocMount := filepath.Join(root, allocdir.SharedAllocContainerPath)
	mounts, err := jail.Mounts(root)
	if err != nil {
		return "", false
	}
	for _, m := range mounts {
		if m.On != allocMount || m.Type != "nullfs" {
			continue
		}
		if _, err := os.Stat(m.From); os.IsNotExist(err) {
			return "its allocation directory " + m.From + " is gone", true
		}
		return "", false
	}

	// No /alloc at all: half built or half torn down, with no task behind
	// it.
	return "it has no allocation directory mounted", true
}

// InspectTask returns detailed status for a task.
func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}
	return handle.TaskStatus(), nil
}

// TaskStats returns a channel of resource usage reports for a task.
func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}
	return handle.exec.Stats(ctx, interval)
}

// TaskEvents returns a channel the driver emits task events on.
func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

// emitEvent reports something the operator should see in the allocation's
// status: the driver carried on, but not as the job asked.
func (d *Driver) emitEvent(cfg *drivers.TaskConfig, format string, args ...any) {
	if err := d.eventer.EmitEvent(&drivers.TaskEvent{
		TaskID:    cfg.ID,
		TaskName:  cfg.Name,
		AllocID:   cfg.AllocID,
		Timestamp: time.Now(),
		Message:   fmt.Sprintf(format, args...),
	}); err != nil {
		d.logger.Trace("could not emit task event", "error", err)
	}
}

// SignalTask forwards a signal to a task's process.
func (d *Driver) SignalTask(taskID string, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	sig, ok := signals.SignalLookup[signal]
	if !ok {
		return fmt.Errorf("unknown signal %q", signal)
	}
	return handle.exec.Signal(sig)
}

// ExecTask runs a command in a task's jail and returns its output.  Nomad uses
// it for script checks.
func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	if len(cmd) == 0 {
		return nil, errors.New("command is required")
	}
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	jexecCmd := handle.jexecPrefix()
	out, exitCode, err := handle.exec.Exec(time.Now().Add(timeout), jexecCmd[0], append(jexecCmd[1:], cmd...))
	if err != nil {
		return nil, err
	}
	return &drivers.ExecTaskResult{
		Stdout:     out,
		ExitResult: &drivers.ExitResult{ExitCode: exitCode},
	}, nil
}

// ExecTaskStreamingRaw runs a command in a task's jail with its streams
// attached, for `nomad alloc exec`.
func (d *Driver) ExecTaskStreamingRaw(
	ctx context.Context,
	taskID string,
	command []string,
	tty bool,
	stream drivers.ExecTaskStream,
) error {
	if len(command) == 0 {
		return errors.New("command is required")
	}
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}
	return handle.exec.ExecStreaming(ctx, append(handle.jexecPrefix(), command...), tty, stream)
}

// Shutdown stops the driver's subsystems.  Nomad stops a plugin by killing it;
// this is for tests.
func (d *Driver) Shutdown() {
	d.signalShutdown()
}

var (
	_ drivers.DriverPlugin               = (*Driver)(nil)
	_ drivers.ExecTaskStreamingRawDriver = (*Driver)(nil)
)
