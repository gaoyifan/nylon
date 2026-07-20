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
}
