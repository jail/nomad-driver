// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package jail

import (
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Flags for Set and Get, from <sys/jail.h>.
const (
	// FlagCreate creates the jail if it does not exist.
	FlagCreate = 0x01
	// FlagUpdate updates the parameters of an existing jail.
	FlagUpdate = 0x02
	// FlagAttach attaches the calling thread to the jail; see Attach.
	FlagAttach = 0x04
	// FlagDying permits operating on a jail that is being torn down.
	FlagDying = 0x08
)

// Pseudo-parameters, which address a jail or carry out-of-band data.
const (
	ParamJID     = "jid"
	ParamName    = "name"
	ParamPath    = "path"
	ParamLastJID = "lastjid"
	ParamDesc    = "desc"
	ParamErrmsg  = "errmsg"
	ParamDying   = "dying"
	ParamPersist = "persist"
)

// errmsgLen is JAIL_ERRMSGLEN from <sys/jail.h>.
const errmsgLen = 1024

// arrayProbeSlop is the room, in elements, left for an array parameter to grow
// between sizing and fetching it.  It is ARRAY_SLOP in libjail.
const arrayProbeSlop = 5

// Param is a jail parameter and its value in the syntax of jail.conf(5).  An
// empty Value means true for a boolean, the empty string for a string, and
// removal for a key/value parameter such as env.FOO.
type Param struct {
	Name  string
	Value string
}

func (p Param) String() string {
	if p.Value == "" {
		return p.Name
	}
	return p.Name + "=" + p.Value
}

// IntParam returns an integer-valued parameter.
func IntParam(name string, value int) Param {
	return Param{Name: name, Value: strconv.Itoa(value)}
}

// Error reports a failed jail_set(2) or jail_get(2).  Msg is the kernel's
// errmsg, if it gave one.
type Error struct {
	Op  string
	Msg string
	Err error
}

func (e *Error) Error() string {
	switch {
	case e.Msg != "" && e.Err != nil:
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Msg, e.Err)
	case e.Msg != "":
		return e.Op + ": " + e.Msg
	default:
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
}

func (e *Error) Unwrap() error { return e.Err }

// ErrNotFound is reported when no jail matches the given name or ID.
var ErrNotFound = errors.New("jail not found")

// iovecs accumulates the name/value pairs of a jail_set(2) or jail_get(2) call.
// Base holds real Go pointers, which keeps the buffers reachable for as long as
// the slice is.
type iovecs []unix.Iovec

func (v *iovecs) add(name string, value []byte) {
	*v = append(*v, iovecFor(nulTerminate(name)), iovecFor(value))
}

func iovecFor(b []byte) unix.Iovec {
	var iov unix.Iovec
	if len(b) > 0 {
		iov.Base = &b[0]
	}
	iov.SetLen(len(b))
	return iov
}

// errmsg appends the "errmsg" parameter and returns its buffer.
func (v *iovecs) errmsg() []byte {
	buf := make([]byte, errmsgLen)
	v.add(ParamErrmsg, buf)
	return buf
}

// Set creates or updates a jail and returns its ID.  It is the equivalent of
// jailparam_set(3).
func Set(flags int, params ...Param) (int, error) {
	var iov iovecs
	for _, p := range params {
		pt, err := lookupParam(p.Name)
		if err != nil {
			return 0, &Error{Op: "jail_set", Err: err}
		}
		name, value, err := pt.encode(p.Name, p.Value)
		if err != nil {
			return 0, &Error{Op: "jail_set", Err: err}
		}
		iov.add(name, value)
	}
	msg := iov.errmsg()

	jid, _, errno := unix.Syscall(unix.SYS_JAIL_SET,
		uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), uintptr(flags))
	if errno != 0 {
		return 0, &Error{Op: "jail_set", Msg: trimNul(msg), Err: errno}
	}
	return int(jid), nil
}

// Get reads the named parameters of the jail selected by key.  It is the
// equivalent of jailparam_get(3).  Parameters the kernel does not publish are
// left out of the result rather than failing the call.
func Get(flags int, key Param, names ...string) (map[string]string, error) {
	keyType, err := lookupParam(key.Name)
	if err != nil {
		return nil, &Error{Op: "jail_get", Err: err}
	}
	keyName, keyValue, err := keyType.encode(key.Name, key.Value)
	if err != nil {
		return nil, &Error{Op: "jail_get", Err: err}
	}

	types := make([]*paramType, 0, len(names))
	wanted := make([]string, 0, len(names))
	for _, name := range names {
		// The key is in the request already and must not be in it
		// twice.
		if name == key.Name {
			continue
		}
		pt, err := lookupParam(name)
		if err != nil {
			if errors.Is(err, errUnknownParam) {
				continue
			}
			return nil, &Error{Op: "jail_get", Err: err}
		}
		types = append(types, pt)
		wanted = append(wanted, name)
	}

	// An array parameter has no fixed size.  Passing a NULL value makes the
	// kernel write the length it needs back into the iovec.
	sizes := make([]int, len(types))
	for i, pt := range types {
		sizes[i] = pt.width
		if !pt.array {
			continue
		}
		var probe iovecs
		probe.add(wanted[i], nil)
		probe.add(keyName, keyValue)
		pmsg := probe.errmsg()

		if _, _, errno := unix.Syscall(unix.SYS_JAIL_GET,
			uintptr(unsafe.Pointer(&probe[0])), uintptr(len(probe)), uintptr(flags)); errno != 0 {
			return nil, getError(trimNul(pmsg), errno)
		}
		sizes[i] = int(probe[1].Len) + pt.width*arrayProbeSlop
	}

	var iov iovecs
	bufs := make([][]byte, len(types))
	for i := range types {
		bufs[i] = make([]byte, sizes[i])
		iov.add(wanted[i], bufs[i])
	}
	iov.add(keyName, keyValue)
	msg := iov.errmsg()

	if _, _, errno := unix.Syscall(unix.SYS_JAIL_GET,
		uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), uintptr(flags)); errno != 0 {
		return nil, getError(trimNul(msg), errno)
	}

	out := make(map[string]string, len(types)+1)
	if key.Name != ParamLastJID {
		out[key.Name] = key.Value
	}
	for i, pt := range types {
		n := int(iov[2*i+1].Len)
		if n > len(bufs[i]) {
			n = len(bufs[i])
		}
		s, err := pt.decode(bufs[i][:n])
		if err != nil {
			return nil, &Error{Op: "jail_get", Err: err}
		}
		out[wanted[i]] = s
	}
	return out, nil
}

func getError(msg string, errno unix.Errno) error {
	if errno == unix.ENOENT {
		return fmt.Errorf("%w: %s", ErrNotFound, msg)
	}
	return &Error{Op: "jail_get", Msg: msg, Err: errno}
}

// Attach moves the calling thread into the jail.  It is the equivalent of
// jail_attach(2).
//
// The credential change applies to one thread, and the Go runtime moves
// goroutines between threads, so this is only safe between fork and exec.  Use
// jexec(8) to run something in a jail.
func Attach(jid int) error {
	if _, _, errno := unix.Syscall(unix.SYS_JAIL_ATTACH, uintptr(jid), 0, 0); errno != 0 {
		return &Error{Op: "jail_attach", Err: errno}
	}
	return nil
}

// Remove removes a jail, killing every process in it.  It is the equivalent of
// jail_remove(2), and reports ErrNotFound if there is no such jail.
func Remove(jid int) error {
	if _, _, errno := unix.Syscall(unix.SYS_JAIL_REMOVE, uintptr(jid), 0, 0); errno != 0 {
		if errno == unix.EINVAL {
			return fmt.Errorf("%w: jid %d", ErrNotFound, jid)
		}
		return &Error{Op: "jail_remove", Err: errno}
	}
	return nil
}

// FindID returns the ID of the named jail.  It is the equivalent of
// jail_getid(3): an all-digit name is taken as an ID.
func FindID(name string) (int, error) {
	key := Param{Name: ParamName, Value: name}
	if _, err := strconv.Atoi(name); err == nil {
		key = Param{Name: ParamJID, Value: name}
	}
	got, err := Get(0, key, ParamJID)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(got[ParamJID])
}

// Info describes a jail, as jls(8) reports it.
type Info struct {
	JID      int
	Name     string
	Path     string
	Hostname string
	Dying    bool
}

// infoParams are the parameters behind Info.  Every kernel publishes them.
var infoParams = []string{ParamJID, ParamName, ParamPath, "host.hostname", ParamDying}

// Inspect returns the state of one jail, by name or numeric ID.  A dying jail
// is reported, with Dying set.
func Inspect(name string) (Info, error) {
	key := Param{Name: ParamName, Value: name}
	if _, err := strconv.Atoi(name); err == nil {
		key = Param{Name: ParamJID, Value: name}
	}
	got, err := Get(FlagDying, key, infoParams...)
	if err != nil {
		return Info{}, err
	}
	return infoFrom(got)
}

// List returns every jail on the system, dying ones included, by walking
// "lastjid" as jls(8) does.
func List() ([]Info, error) {
	var out []Info
	for last := 0; ; {
		got, err := Get(FlagDying, IntParam(ParamLastJID, last), infoParams...)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return out, nil
			}
			return nil, err
		}
		info, err := infoFrom(got)
		if err != nil {
			return nil, err
		}
		out = append(out, info)

		if info.JID <= last {
			// A jid that does not advance would loop forever.
			return out, fmt.Errorf("jail_get: lastjid did not advance past %d", last)
		}
		last = info.JID
	}
}

func infoFrom(got map[string]string) (Info, error) {
	jid, err := strconv.Atoi(got[ParamJID])
	if err != nil {
		return Info{}, fmt.Errorf("jail_get: bad jid %q: %w", got[ParamJID], err)
	}
	dying, _ := parseBool(got[ParamDying])
	return Info{
		JID:      jid,
		Name:     got[ParamName],
		Path:     got[ParamPath],
		Hostname: got["host.hostname"],
		Dying:    dying,
	}, nil
}

// Exists reports whether a jail with the given name is present and not dying.
func Exists(name string) (bool, int, error) {
	jid, err := FindID(name)
	switch {
	case errors.Is(err, ErrNotFound):
		return false, 0, nil
	case err != nil:
		return false, 0, err
	}
	return true, jid, nil
}

// HasParam reports whether the running kernel publishes the named parameter,
// which is how to test for optional features: "vnet" needs VIMAGE,
// "allow.mount.zfs" the ZFS module.
func HasParam(name string) bool {
	_, err := lookupParam(name)
	return err == nil
}
