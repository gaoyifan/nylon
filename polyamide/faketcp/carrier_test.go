package faketcp

import "testing"

func TestFoldPayloadChecksum(t *testing.T) {
	tests := []struct {
		payload []byte
		want    uint16
	}{
		{nil, 0},
		{[]byte{0x12}, 0x1200},
		{[]byte{0x12, 0x34}, 0x1234},
		{[]byte{0xff, 0xff, 0, 1}, 1},
		{[]byte{0xff, 0xff, 0xff, 0xff}, 0xffff},
	}
	for _, test := range tests {
		if got := FoldPayloadChecksum(test.payload); got != test.want {
			t.Fatalf("FoldPayloadChecksum(%x) = %#x, want %#x", test.payload, got, test.want)
		}
	}

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	for length := 0; length <= len(payload); length++ {
		var want uint64
		for i := 0; i+1 < length; i += 2 {
			want += uint64(payload[i])<<8 | uint64(payload[i+1])
		}
		if length&1 != 0 {
			want += uint64(payload[length-1]) << 8
		}
		for want>>16 != 0 {
			want = want&0xffff + want>>16
		}
		if got := FoldPayloadChecksum(payload[:length]); got != uint16(want) {
			t.Fatalf("length %d checksum = %#x, want %#x", length, got, want)
		}
	}
}

func BenchmarkFoldPayloadChecksum(b *testing.B) {
	payload := make([]byte, 1408)
	for i := range payload {
		payload[i] = byte(i)
	}
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		FoldPayloadChecksum(payload)
	}
}
