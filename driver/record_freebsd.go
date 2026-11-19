// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>
//
// SPDX-License-Identifier: BSD-2-Clause

package driver

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/jail/nomad-driver/jail"
	"golang.org/x/sys/unix"
)

// recordDir is where the driver keeps a record of each jail it makes.  It is
// under /var/run because nothing a record describes outlives the boot.
const recordDir = "/var/run/jail-nomad-driver"

const (
	recordVersion = 1
	recordSuffix  = ".json"
	recordMaxSize = 1 << 20
)

// jailRecord is a jail's state as kept on disk.  The task handle has the same
// state, but only for as long as Nomad remembers the allocation; the record is
// for a driver that finds the jail, or what is left of it, without one.
type jailRecord struct {
	Version int `json:"version"`

	// BootID is kern.boot_id as it was when the record was written.  What
	// a record from another boot describes is gone, and its names may be
	// somebody else's by now.
	BootID string `json:"boot_id"`

	Jail jailState `json:"jail"`
}

// recordStore keeps jail records in a directory, one file to a jail.
type recordStore struct {
	dir    string
	bootID string
}

func newRecordStore(dir string) *recordStore {
	return &recordStore{dir: dir, bootID: bootID()}
}

// bootID identifies this boot of the kernel.  It is "" where the kernel cannot
// say, and then no record is believed.
func bootID() string {
	raw, err := unix.SysctlRaw("kern.boot_id")
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

// path returns the file a jail's record is kept in, or "" for a name that
// would not stay in the directory.
func (r *recordStore) path(name string) string {
	if name == "" || strings.HasPrefix(name, ".") || filepath.Base(name) != name {
		return ""
	}
	return filepath.Join(r.dir, name+recordSuffix)
}

// save writes a jail's record in place of the one it had.
func (r *recordStore) save(st *jailState) error {
	path := r.path(st.Name)
	if path == "" {
		return fmt.Errorf("no record can be kept for a jail named %q", st.Name)
	}
	data, err := json.Marshal(jailRecord{Version: recordVersion, BootID: r.bootID, Jail: *st})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return err
	}

	// Renamed into place, so that a reader finds the old record or the new
	// one and never part of either.
	tmp, err := os.CreateTemp(r.dir, ".record-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}

// load returns the state in a jail's record, or nil if it has no record that
// can be believed.  One that cannot is removed.
func (r *recordStore) load(name string) *jailState {
	path := r.path(name)
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var rec jailRecord
	data, err := io.ReadAll(io.LimitReader(f, recordMaxSize))
	if err == nil {
		err = json.Unmarshal(data, &rec)
	}
	if err != nil || rec.Version != recordVersion || rec.Jail.Name != name ||
		rec.BootID == "" || rec.BootID != r.bootID {
		_ = os.Remove(path)
		return nil
	}
	return &rec.Jail
}

func (r *recordStore) remove(name string) {
	if path := r.path(name); path != "" {
		_ = os.Remove(path)
	}
}

// names lists the jails that have a record.
func (r *recordStore) names() []string {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		name, isRecord := strings.CutSuffix(e.Name(), recordSuffix)
		if !isRecord || !e.Type().IsRegular() || r.path(name) == "" {
			// What a save that was cut short left.
			if strings.HasPrefix(e.Name(), ".record-") {
				_ = os.Remove(filepath.Join(r.dir, e.Name()))
			}
			continue
		}
		names = append(names, name)
	}
	return names
}

// stateOf returns the state of a jail found on the system: what its record
// says if it has one, and what can be worked out from the jail itself if not.
func (d *Driver) stateOf(info jail.Info) *jailState {
	if st := d.records.load(info.Name); st != nil && st.Root == info.Path {
		st.JID = info.JID
		return st
	}
	return d.reclaimState(info)
}

// remains returns what the record of a jail that is gone says is left of it,
// or nil.
func (d *Driver) remains(logger hclog.Logger, name string) *jailState {
	st := d.records.load(name)
	if st == nil {
		return nil
	}
	if st.Dataset == "" {
		st.Dataset = d.cloneOf(name)
	}
	// With its jail gone a root the job named may be another jail's by
	// now, and what is mounted there the other's.
	if len(st.Mounts) > 0 && rootInUse(st.Root) {
		logger.Warn("leaving the mounts of a jail that is gone: another jail has its root",
			"jail", name, "root", st.Root, "mounts", st.Mounts)
		st.Mounts = nil
	}
	return st
}

// rootInUse reports whether a jail is rooted at root.  It errs towards yes.
func rootInUse(root string) bool {
	jails, err := jail.List()
	if err != nil {
		return true
	}
	for _, info := range jails {
		if info.Path == root && !info.Dying {
			return true
		}
	}
	return false
}

// leftover returns the state of what an earlier run of a task left behind, or
// nil: its jail if that is still there, and otherwise what its record says.
func (d *Driver) leftover(logger hclog.Logger, name string) (*jailState, error) {
	info, err := jail.Inspect(name)
	switch {
	case err == nil && !info.Dying:
		return d.stateOf(info), nil
	case err == nil, errors.Is(err, jail.ErrNotFound):
		return d.remains(logger, name), nil
	default:
		return nil, fmt.Errorf("looking for an existing jail named %s: %w", name, err)
	}
}

// reapRemains tears down what the records say is left of jails that are gone
// and that no task is coming back for: a start or a teardown that was cut
// short.  alive holds the jails that are still there.
func (d *Driver) reapRemains(alive map[string]bool) {
	for _, name := range d.records.names() {
		if alive[name] {
			continue
		}
		st := d.remains(d.logger, name)
		if st == nil {
			continue
		}
		// Nomad keeps the allocation directory for as long as it means
		// to recover the allocation, and will be back for this one.
		if st.AllocDir != "" {
			if _, err := os.Stat(st.AllocDir); !os.IsNotExist(err) {
				continue
			}
		}
		d.logger.Warn("reaping what an orphaned jail left behind", "jail", name)
		if err := d.teardown(d.logger, st); err != nil {
			d.logger.Error("could not reap what the jail left", "jail", name, "error", err)
		}
	}
}
