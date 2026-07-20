// Package faketcp contains the carrier format shared by Nylon's fake TCP bind
// and its Linux TCX transformer.
package faketcp

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
	var sum uint32
	for len(payload) >= 16 {
		sum += uint32(payload[0])<<8 | uint32(payload[1])
		sum += uint32(payload[2])<<8 | uint32(payload[3])
		sum += uint32(payload[4])<<8 | uint32(payload[5])
		sum += uint32(payload[6])<<8 | uint32(payload[7])
		sum += uint32(payload[8])<<8 | uint32(payload[9])
		sum += uint32(payload[10])<<8 | uint32(payload[11])
		sum += uint32(payload[12])<<8 | uint32(payload[13])
		sum += uint32(payload[14])<<8 | uint32(payload[15])
		payload = payload[16:]
	}
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
