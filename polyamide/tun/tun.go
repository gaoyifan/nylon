/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"os"
)

type Event int

const (
	EventUp = 1 << iota
	EventDown
	EventMTUUpdate
)

// EthPMplsUnicast is the ETH_P_MPLS_UC ethertype, reported via the tun_pi
// header for MPLS unicast packets when the device runs in PI mode.
const EthPMplsUnicast uint16 = 0x8847

// ProtoReader is optionally implemented by Devices that can report the L3
// protocol (ethertype) of each packet from the most recent Read. It is only
// meaningful for devices opened in packet-information (PI) mode; other devices
// need not implement it.
type ProtoReader interface {
	// LastReadProtos returns a slice parallel to the packets returned by the
	// most recent Read call; element i is the ethertype of packet i. The
	// returned slice is owned by the Device and valid until the next Read.
	LastReadProtos() []uint16
}

// ProtoWriter is optionally implemented by Devices that can emit non-IP frames
// (e.g. MPLS) back to the kernel. It is only meaningful for devices opened in
// packet-information (PI) mode, where the tun_pi proto carries the ethertype.
type ProtoWriter interface {
	// WriteWithProtos behaves like Write, but protos[i] is the ethertype of
	// bufs[i]; a zero entry means "infer from the IP version nibble". protos
	// may be shorter than bufs (missing entries are treated as zero).
	WriteWithProtos(bufs [][]byte, offset int, protos []uint16) (int, error)
}

type Device interface {
	// File returns the file descriptor of the device.
	File() *os.File

	// Read one or more packets from the Device (without any additional headers).
	// On a successful read it returns the number of packets read, and sets
	// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
	// A nonzero offset can be used to instruct the Device on where to begin
	// reading into each element of the bufs slice.
	Read(bufs [][]byte, sizes []int, offset int) (n int, err error)

	// Write one or more packets to the device (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the bufs slice.
	Write(bufs [][]byte, offset int) (int, error)

	// MTU returns the MTU of the Device.
	MTU() (int, error)

	// Name returns the current name of the Device.
	Name() (string, error)

	// Events returns a channel of type Event, which is fed Device events.
	Events() <-chan Event

	// Close stops the Device and closes the Event channel.
	Close() error

	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call. BatchSize must not change over the
	// lifetime of a Device.
	BatchSize() int
}
