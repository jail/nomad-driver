// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package jail

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// sysctlJailParam is the node under which the kernel describes each jail
// parameter's type.
const sysctlJailParam = "security.jail.param"

// sizeofLong is the width of a C long, which on every FreeBSD architecture Go
// supports is that of Go's int.
const sizeofLong = strconv.IntSize / 8

type paramFlags uint8

const (
	// flagBool marks a boolean parameter named affirmatively ("persist").
	flagBool paramFlags = 1 << iota
	// flagNoBool marks a boolean parameter named negatively ("nopersist").
	flagNoBool
	// flagJailSys marks an "E,jailsys" enum: disable, new or inherit.
	flagJailSys
	// flagKeyValue marks a member of an "A,keyvalue" node, such as env.FOO.
	flagKeyValue
)

// paramType is the resolved type of a jail parameter: what jailparam_init(3)
// derives from the sysctl tree.
type paramType struct {
	// name is the name the sysctl tree knows, which for a negated boolean
	// or a key/value member is not the one the caller used.
	name string
	// kind is the CTLTYPE_*|CTLFLAG_* word from the describing sysctl.
	kind uint32
	// format is the sysctl format string without any array suffix: "I",
	// "B", "E,jailsys", "S,in_addr".
	format string
	// width is the size in bytes of a scalar, of one element of an array,
	// or of a string's buffer including the NUL.
	width int
	// array reports whether the parameter is a ",a" array.
	array bool
	flags paramFlags
}

func (p *paramType) ctltype() uint32 { return p.kind & ctltypeMask }

// errUnknownParam is returned for a name the kernel does not publish.
var errUnknownParam = errors.New("unknown jail parameter")

// paramCache memoises successful lookups, each of which costs several sysctl
// calls.  Failures are not cached: a kldload can make a parameter appear.
var paramCache sync.Map // string -> *paramType

// lookupParam resolves name against the kernel's jail parameter list.  It
// follows jailparam_type() in libjail, without the kldload-on-demand and MAC
// label handling.
func lookupParam(name string) (*paramType, error) {
	if p, ok := paramCache.Load(name); ok {
		return p.(*paramType), nil
	}
	p, err := resolveParam(name)
	if err != nil {
		return nil, err
	}
	paramCache.Store(name, p)
	return p, nil
}

func resolveParam(name string) (*paramType, error) {
	// Pseudo-parameters are not in the sysctl tree.
	switch name {
	case ParamLastJID, ParamDesc:
		return &paramType{name: name, kind: ctltypeInt, format: "I", width: 4}, nil
	case ParamErrmsg:
		return &paramType{name: name, kind: ctltypeString, format: "A", width: errmsgLen}, nil
	}

	oid, err := nameToOID(sysctlJailParam + "." + name)
	switch {
	case err == nil:
		return (&paramType{name: name}).describe(oid)
	case !errors.Is(err, unix.ENOENT):
		return nil, fmt.Errorf("sysctl %s.%s: %w", sysctlJailParam, name, err)
	}

	// It may be the negated spelling of a boolean...
	if affirm, aerr := affirmName(name); aerr == nil {
		if oid, err := nameToOID(sysctlJailParam + "." + affirm); err == nil {
			return (&paramType{name: affirm, flags: flagNoBool}).describe(oid)
		}
	}

	// ...or a member of a key/value node such as env.FOO or meta.owner.
	if node := keyValueName(name); node != "" {
		if oid, err := nameToOID(sysctlJailParam + "." + node); err == nil {
			return (&paramType{name: node, flags: flagKeyValue}).describe(oid)
		}
	}

	return nil, fmt.Errorf("%w: %s", errUnknownParam, name)
}

// describe fills in p from the describing sysctl at oid, following at most one
// CTLTYPE_NODE indirection, as libjail does.
func (p *paramType) describe(oid []int32) (*paramType, error) {
	for indirected := false; ; indirected = true {
		kind, format, err := oidFormat(oid)
		if err != nil {
			return nil, fmt.Errorf("sysctl oidfmt %s.%s: %w", sysctlJailParam, p.name, err)
		}
		p.kind = kind
		p.format, p.array = strings.CutSuffix(format, ",a")

		if p.flags&flagNoBool != 0 && !isBoolFormat(p.ctltype(), p.format) && p.ctltype() != ctltypeNode {
			// The name came from stripping a "no", so it has to be
			// a boolean or a node of them.
			return nil, fmt.Errorf("%w: no%s", errUnknownParam, p.name)
		}
		if p.flags&flagKeyValue != 0 && (p.ctltype() != ctltypeString || format != "A,keyvalue") {
			return nil, fmt.Errorf("%w: %s.*", errUnknownParam, p.name)
		}

		if p.ctltype() != ctltypeNode {
			break
		}
		if indirected {
			return nil, fmt.Errorf("%w: %s", errUnknownParam, p.name)
		}
		if oid, err = nodeDescriptor(oid, p.name); err != nil {
			return nil, err
		}
	}

	switch p.ctltype() {
	case ctltypeInt:
		switch {
		case isBoolFormat(ctltypeInt, p.format):
			// flagNoBool is set already if the caller used the
			// negated name; the two are exclusive.
			if p.flags&flagNoBool == 0 {
				p.flags |= flagBool
			}
		case p.format == "E,jailsys":
			p.flags |= flagJailSys
		}
		p.width = 4
	case ctltypeUint, ctltypeS32, ctltypeU32:
		p.width = 4
	case ctltypeU8, ctltypeS8:
		p.width = 1
	case ctltypeU16, ctltypeS16:
		p.width = 2
	case ctltypeLong, ctltypeUlong:
		p.width = sizeofLong
	case ctltypeS64, ctltypeU64:
		p.width = 8
	case ctltypeString:
		// A string parameter's sysctl value is its maximum length, in
		// decimal.
		s, err := oidValueString(oid)
		if err != nil {
			return nil, fmt.Errorf("sysctl %s.%s: %w", sysctlJailParam, p.name, err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("jail parameter %s: bad maximum length %q", p.name, s)
		}
		p.width = n
	case ctltypeStruct:
		switch p.format {
		case "S,in_addr":
			p.width = net.IPv4len
		case "S,in6_addr":
			p.width = net.IPv6len
		default:
			n, err := oidValueLen(oid)
			if err != nil {
				return nil, fmt.Errorf("sysctl %s.%s: %w", sysctlJailParam, p.name, err)
			}
			p.width = n
		}
	default:
		return nil, fmt.Errorf("jail parameter %s: unsupported type (format %q)", p.name, p.format)
	}

	return p, nil
}

// isBoolFormat reports whether a CTLTYPE_INT parameter is a boolean, which the
// kernel gives the format "B".
func isBoolFormat(ctltype uint32, format string) bool {
	return ctltype == ctltypeInt && strings.HasPrefix(format, "B")
}

// nodeDescriptor finds the empty-named child that describes a CTLTYPE_NODE
// parameter, such as security.jail.param.ip4. for ip4.  OID_AUTO numbers are
// sequential and the node and its descriptor are registered together, so the
// descriptor's number is one either side of the node's.
func nodeDescriptor(oid []int32, name string) ([]int32, error) {
	want := sysctlJailParam + "." + name + "."

	for _, delta := range []int32{-1, 1} {
		child := make([]int32, len(oid), len(oid)+1)
		copy(child, oid)
		child = append(child, oid[len(oid)-1]+delta)

		got, err := oidName(child)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return nil, fmt.Errorf("sysctl oidname %s: %w", name, err)
		}
		if got == want {
			return child, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", errUnknownParam, name)
}

// encode converts a textual value into what jail_set(2) expects.
//
// It returns the name to send, which for a false boolean is the negated one,
// and the encoded bytes.  The bytes are nil for a boolean and for a key/value
// removal, both of which the kernel takes as a zero-length value.
func (p *paramType) encode(name, value string) (string, []byte, error) {
	switch {
	case p.flags&(flagBool|flagNoBool) != 0:
		// A bare "persist" means true, as in jail.conf(5).
		on := true
		if value != "" {
			v, err := parseBool(value)
			if err != nil {
				return "", nil, fmt.Errorf("jail parameter %s: %w", name, err)
			}
			on = v
		}
		if on {
			return name, nil, nil
		}
		if p.flags&flagNoBool != 0 {
			affirm, err := affirmName(name)
			return affirm, nil, err
		}
		return negateName(name), nil, nil

	case p.flags&flagJailSys != 0:
		v, ok := jailSysValues[value]
		if !ok {
			return "", nil, fmt.Errorf("jail parameter %s: want disable, new or inherit, got %q",
				name, value)
		}
		return name, binary.NativeEndian.AppendUint32(nil, uint32(v)), nil

	case p.flags&flagKeyValue != 0:
		// An absent value removes the key.
		if value == "" {
			return name, nil, nil
		}
		return name, nulTerminate(value), nil

	case p.array:
		var buf []byte
		// An empty value is an empty array: ip4.addr="" clears the
		// list.
		if value != "" {
			for _, elem := range strings.Split(value, ",") {
				b, err := p.encodeScalar(name, strings.TrimSpace(elem))
				if err != nil {
					return "", nil, err
				}
				buf = append(buf, b...)
			}
		}
		return name, buf, nil
	}

	b, err := p.encodeScalar(name, value)
	return name, b, err
}

var jailSysValues = map[string]int32{"disable": 0, "new": 1, "inherit": 2}

var jailSysNames = [...]string{"disable", "new", "inherit"}

func (p *paramType) encodeScalar(name, value string) ([]byte, error) {
	switch p.ctltype() {
	case ctltypeString:
		if len(value)+1 > p.width {
			return nil, fmt.Errorf("jail parameter %s: value needs %d bytes, limit is %d",
				name, len(value)+1, p.width)
		}
		return nulTerminate(value), nil

	case ctltypeStruct:
		switch p.format {
		case "S,in_addr":
			ip := net.ParseIP(value)
			if ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("jail parameter %s: %q is not an IPv4 address", name, value)
			}
			return ip.To4(), nil
		case "S,in6_addr":
			ip := net.ParseIP(value)
			if ip == nil || ip.To4() != nil || ip.To16() == nil {
				return nil, fmt.Errorf("jail parameter %s: %q is not an IPv6 address", name, value)
			}
			return ip.To16(), nil
		}
		return nil, fmt.Errorf("jail parameter %s: no textual form for %q", name, p.format)
	}

	// Everything left is an integer.  Parse it signed or unsigned to match
	// the kernel's type, then store it in the kernel's width.
	var raw uint64
	if isUnsigned(p.ctltype()) {
		v, err := strconv.ParseUint(value, 0, p.width*8)
		if err != nil {
			return nil, fmt.Errorf("jail parameter %s: %w", name, err)
		}
		raw = v
	} else {
		v, err := strconv.ParseInt(value, 0, p.width*8)
		if err != nil {
			return nil, fmt.Errorf("jail parameter %s: %w", name, err)
		}
		raw = uint64(v)
	}

	buf := make([]byte, p.width)
	switch p.width {
	case 1:
		buf[0] = byte(raw)
	case 2:
		binary.NativeEndian.PutUint16(buf, uint16(raw))
	case 4:
		binary.NativeEndian.PutUint32(buf, uint32(raw))
	case 8:
		binary.NativeEndian.PutUint64(buf, raw)
	default:
		return nil, fmt.Errorf("jail parameter %s: unsupported width %d", name, p.width)
	}
	return buf, nil
}

// decode renders a raw parameter value as text.  It is the equivalent of
// jailparam_export(3).
func (p *paramType) decode(raw []byte) (string, error) {
	if !p.array {
		return p.decodeScalar(raw)
	}
	if p.width == 0 || len(raw)%p.width != 0 {
		return "", fmt.Errorf("jail parameter %s: %d bytes is not a whole number of %d-byte elements",
			p.name, len(raw), p.width)
	}
	elems := make([]string, 0, len(raw)/p.width)
	for off := 0; off < len(raw); off += p.width {
		s, err := p.decodeScalar(raw[off : off+p.width])
		if err != nil {
			return "", err
		}
		elems = append(elems, s)
	}
	return strings.Join(elems, ","), nil
}

func (p *paramType) decodeScalar(raw []byte) (string, error) {
	switch p.ctltype() {
	case ctltypeString:
		return trimNul(raw), nil

	case ctltypeStruct:
		switch p.format {
		case "S,in_addr":
			if len(raw) < net.IPv4len {
				return "", fmt.Errorf("jail parameter %s: short in_addr", p.name)
			}
			return net.IP(raw[:net.IPv4len]).String(), nil
		case "S,in6_addr":
			if len(raw) < net.IPv6len {
				return "", fmt.Errorf("jail parameter %s: short in6_addr", p.name)
			}
			return net.IP(raw[:net.IPv6len]).String(), nil
		}
		return "", fmt.Errorf("jail parameter %s: no textual form for %q", p.name, p.format)
	}

	var u uint64
	switch len(raw) {
	case 1:
		u = uint64(raw[0])
	case 2:
		u = uint64(binary.NativeEndian.Uint16(raw))
	case 4:
		u = uint64(binary.NativeEndian.Uint32(raw))
	case 8:
		u = binary.NativeEndian.Uint64(raw)
	default:
		return "", fmt.Errorf("jail parameter %s: unsupported width %d", p.name, len(raw))
	}

	switch {
	case p.flags&flagJailSys != 0:
		if u >= uint64(len(jailSysNames)) {
			return "", fmt.Errorf("jail parameter %s: unknown jailsys value %d", p.name, u)
		}
		return jailSysNames[u], nil
	case p.flags&(flagBool|flagNoBool) != 0:
		return strconv.FormatBool(u != 0), nil
	case isUnsigned(p.ctltype()):
		return strconv.FormatUint(u, 10), nil
	}

	// Sign-extend from the kernel's width.
	shift := 64 - 8*len(raw)
	return strconv.FormatInt(int64(u<<shift)>>shift, 10), nil
}

func isUnsigned(ctltype uint32) bool {
	switch ctltype {
	case ctltypeUint, ctltypeUlong, ctltypeU64, ctltypeU8, ctltypeU16, ctltypeU32:
		return true
	}
	return false
}

// parseBool accepts the spellings jail(8) and jail.conf(5) accept.
func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a boolean", s)
}

func nulTerminate(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return b
}

func trimNul(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
