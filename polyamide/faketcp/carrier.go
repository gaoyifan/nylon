// Package faketcp contains the carrier format shared by Nylon's fake TCP bind
// and its Linux TCX transformer.
package faketcp

import "encoding/binary"

const (
	CarrierMagic      uint16 = 0x4e59
	CarrierHeaderSize        = 12
	FrameHeaderSize          = 2
	SYNOptionSize            = 4

	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagACK uint8 = 0x10
)

// FoldPayloadChecksum returns the uncomplemented one's-complement sum stored in
// the meta field of an outbound data carrier.
func FoldPayloadChecksum(payload []byte) uint16 {
	var sum uint64
	for len(payload) >= 32 {
		sum += uint64(binary.BigEndian.Uint32(payload[0:4]))
		sum += uint64(binary.BigEndian.Uint32(payload[4:8]))
		sum += uint64(binary.BigEndian.Uint32(payload[8:12]))
		sum += uint64(binary.BigEndian.Uint32(payload[12:16]))
		sum += uint64(binary.BigEndian.Uint32(payload[16:20]))
		sum += uint64(binary.BigEndian.Uint32(payload[20:24]))
		sum += uint64(binary.BigEndian.Uint32(payload[24:28]))
		sum += uint64(binary.BigEndian.Uint32(payload[28:32]))
		payload = payload[32:]
	}
	for len(payload) >= 4 {
		sum += uint64(binary.BigEndian.Uint32(payload[:4]))
		payload = payload[4:]
	}
	if len(payload) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint64(payload[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
