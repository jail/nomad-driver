// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2024-2026 Faraz Vahedi <kfv@FreeBSD.org>

package jail

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// From <sys/sysctl.h>.  x/sys/unix has the FreeBSD syscall numbers but none of
// CTLTYPE_*.
const (
	ctlMaxName = 24

	ctltypeMask   = 0xf
	ctltypeNode   = 1
	ctltypeInt    = 2
	ctltypeString = 3
	ctltypeS64    = 4
	ctltypeStruct = 5
	ctltypeUint   = 6
	ctltypeLong   = 7
	ctltypeUlong  = 8
	ctltypeU64    = 9
	ctltypeU8     = 0xa
	ctltypeU16    = 0xb
	ctltypeS8     = 0xc
	ctltypeS16    = 0xd
	ctltypeS32    = 0xe
	ctltypeU32    = 0xf
)

// The sysctl nodes under oid 0 that describe the tree itself; see sysctl(3) and
// sys/kern/kern_sysctl.c.
const (
	ctlSysctl         = 0
	ctlSysctlName     = 1
	ctlSysctlName2OID = 3
	ctlSysctlOIDFmt   = 4
)

// maxPathLen is MAXPATHLEN, the buffer size libjail uses for format strings and
// sysctl names.
const maxPathLen = 1024

// sysctl wraps sysctl(2) for a numeric MIB, which x/sys/unix does not offer.
// It returns the number of bytes the kernel wrote or, if out is nil, would have
// written.
func sysctl(mib []int32, out, in []byte) (int, error) {
	if len(mib) == 0 || len(mib) > ctlMaxName {
		return 0, unix.EINVAL
	}

	var outp, inp unsafe.Pointer
	outlen := uintptr(len(out))
	if len(out) > 0 {
		outp = unsafe.Pointer(&out[0])
	}
	if len(in) > 0 {
		inp = unsafe.Pointer(&in[0])
	}

	if _, _, errno := unix.Syscall6(unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(outp), uintptr(unsafe.Pointer(&outlen)),
		uintptr(inp), uintptr(len(in)),
	); errno != 0 {
		return 0, errno
	}
	return int(outlen), nil
}

// oidBytes returns a byte view of an OID array.  The slice aliases oid, which
// keeps it reachable.
func oidBytes(oid []int32) []byte {
	if len(oid) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&oid[0])), len(oid)*4)
}

// nameToOID resolves a sysctl name to its OID, as sysctlnametomib(3) does.  The
// name is passed without its NUL, as libc passes it.
func nameToOID(name string) ([]int32, error) {
	mib := []int32{ctlSysctl, ctlSysctlName2OID}
	oid := make([]int32, ctlMaxName)

	n, err := sysctl(mib, oidBytes(oid), []byte(name))
	if err != nil {
		return nil, err
	}
	if n < 4 || n%4 != 0 {
		return nil, fmt.Errorf("sysctl %s: bogus OID length %d", name, n)
	}
	return oid[:n/4], nil
}

// oidFormat returns the kind word (CTLTYPE_* and CTLFLAG_*) and the format
// string of a sysctl, as oidfmt() in sysctl(8) does.
func oidFormat(oid []int32) (kind uint32, format string, err error) {
	mib := make([]int32, 0, len(oid)+2)
	mib = append(mib, ctlSysctl, ctlSysctlOIDFmt)
	mib = append(mib, oid...)

	buf := make([]byte, 4+maxPathLen)
	n, err := sysctl(mib, buf, nil)
	if err != nil {
		return 0, "", err
	}
	if n < 4 {
		return 0, "", fmt.Errorf("sysctl oidfmt: short reply (%d bytes)", n)
	}
	kind = binary.NativeEndian.Uint32(buf[:4])
	format = trimNul(buf[4:n])
	return kind, format, nil
}

// oidName returns the name of an OID.
func oidName(oid []int32) (string, error) {
	mib := make([]int32, 0, len(oid)+2)
	mib = append(mib, ctlSysctl, ctlSysctlName)
	mib = append(mib, oid...)

	buf := make([]byte, maxPathLen)
	n, err := sysctl(mib, buf, nil)
	if err != nil {
		return "", err
	}
	return trimNul(buf[:n]), nil
}

// oidValueString reads a sysctl of type CTLTYPE_STRING by OID.
func oidValueString(oid []int32) (string, error) {
	buf := make([]byte, maxPathLen)
	n, err := sysctl(oid, buf, nil)
	if err != nil {
		return "", err
	}
	return trimNul(buf[:n]), nil
}

// oidValueLen returns the size the kernel reports for a sysctl, which sizes the
// opaque parameters this package cannot convert.
func oidValueLen(oid []int32) (int, error) {
	return sysctl(oid, nil, nil)
}
