// Package faketcp contains the carrier format shared by Nylon's fake TCP bind
// and its Linux TCX transformer.
package faketcp

const (
	CarrierMagic      uint16 = 0x4e59
	CarrierHeaderSize        = 12
	SYNOptionSize            = 4

	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
)

// FoldPayloadChecksum returns the uncomplemented one's-complement sum stored in
// the meta field of an outbound data carrier.
func FoldPayloadChecksum(payload []byte) uint16 {
	var sum uint32
	for len(payload) >= 2 {
		sum += uint32(payload[0])<<8 | uint32(payload[1])
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
