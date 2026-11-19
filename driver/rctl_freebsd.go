// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins/drivers"
)

// rctlRules turns a task's Nomad resources into rctl(8) rules on its jail.
//
// Memory becomes memoryuse:deny, which promises more than it does.  memoryuse
// is resident set size and not deniable; rctl_rule_add() lets the rule through
// as a special case, and vm_daemon enforces it by unmapping pages the jail has
// not referenced since the page daemon last looked.  Nothing is refused and
// nothing is killed: with memory to spare an idle task is over its limit for
// minutes, and a busy one for good.  A job that needs more adds a sigkill,
// swapuse or vmemoryuse rule.
//
// CPU is not translated: Nomad counts MHz and pcpu is a percentage of a core,
// so a conversion would be a guess at the node's clock.  Reserved cores get a
// cpuset instead.
func rctlRules(st *jailState, tc *TaskConfig, res *drivers.Resources) []string {
	var rules []string

	if res != nil && res.NomadResources != nil {
		mem := res.NomadResources.Memory
		// MemoryMaxMB is the oversubscription ceiling, if the job set
		// one, and what the task may reach.
		limit := mem.MemoryMB
		if mem.MemoryMaxMB > limit {
			limit = mem.MemoryMaxMB
		}
		if limit > 0 {
			rules = append(rules, fmt.Sprintf("jail:%s:memoryuse:deny=%dM", st.Name, limit))
		}
	}

	for _, r := range tc.ExtraRCTL {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		// A rule may be given in full, or from the resource on, so that
		// a job need not know the jail's name.
		if strings.HasPrefix(r, "jail:") {
			rules = append(rules, r)
			continue
		}
		rules = append(rules, fmt.Sprintf("jail:%s:%s", st.Name, r))
	}

	return rules
}

// racctEnabled reports whether the kernel will accept rctl(8) rules.  RACCT and
// RCTL are in GENERIC but off until the kern.racct.enable tunable is set.
func racctEnabled() bool {
	v, ok := sysctlInt("kern.racct.enable")
	return ok && v != 0
}

// applyRCTL installs a task's resource limits and returns the rules it added.
//
// Where resource accounting is off, a limit the driver derived is skipped with
// a warning: the node advertises driver.jail.rctl, for a job that needs it to
// constrain on.  A rule the job asked for by name fails the task instead.
func applyRCTL(ctx context.Context, logger hclog.Logger, rules []string, jobAsked bool) ([]string, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	if !racctEnabled() {
		if jobAsked {
			return nil, fmt.Errorf("the task asks for rctl rules but this kernel has resource " +
				"accounting disabled; set the kern.racct.enable tunable in loader.conf(5), " +
				"or constrain the job on the driver.jail.rctl node attribute")
		}
		logger.Warn("not enforcing resource limits: this kernel has resource accounting "+
			"disabled, see the kern.racct.enable tunable", "rules", rules)
		return nil, nil
	}

	var added []string
	for _, rule := range rules {
		if _, err := run(ctx, logger, pathRCTL, "-a", rule); err != nil {
			return added, fmt.Errorf("adding rctl rule %q: %w", rule, err)
		}
		added = append(added, rule)
	}
	return added, nil
}

// removeRCTL removes a task's resource limits.  Removing a jail does not, and
// the next jail of the same name would inherit them.
func removeRCTL(ctx context.Context, logger hclog.Logger, st *jailState) error {
	// By subject, which also catches what a crashed run left under the same
	// name.
	if st.Name == "" || !racctEnabled() {
		return nil
	}
	if _, err := run(ctx, logger, pathRCTL, "-r", "jail:"+st.Name); err != nil {
		// rctl exits non-zero when there is nothing to remove.
		logger.Trace("no rctl rules to remove", "jail", st.Name, "error", err)
	}
	return nil
}

// applyCpuset pins a jail to the cores Nomad reserved for it, if any.
func applyCpuset(ctx context.Context, logger hclog.Logger, jid int, res *drivers.Resources) error {
	if res == nil || res.NomadResources == nil {
		return nil
	}
	cores := res.NomadResources.Cpu.ReservedCores
	if len(cores) == 0 {
		return nil
	}

	list := make([]string, len(cores))
	for i, c := range cores {
		list[i] = strconv.Itoa(int(c))
	}
	if _, err := run(ctx, logger, pathCpuset,
		"-l", strings.Join(list, ","), "-j", strconv.Itoa(jid)); err != nil {
		return fmt.Errorf("pinning jail %d to cores %s: %w", jid, strings.Join(list, ","), err)
	}
	return nil
}
