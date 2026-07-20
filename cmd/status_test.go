package cmd

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/encodeous/nylon/protocol"
)

func TestPrintEndpointsDistinguishesTransportTwins(t *testing.T) {
	resolved := "192.0.2.1:57175"
	endpoints := []*protocol.EndpointInfo{
		{
			Address:   "router.example:57175",
			Resolved:  &resolved,
			Transport: protocol.EndpointTransport_UDP,
		},
		{
			Address:   "router.example:57175",
			Resolved:  &resolved,
			Transport: protocol.EndpointTransport_FAKE_TCP,
		},
	}

	previousStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer func() { os.Stdout = previousStdout }()
	os.Stdout = writer

	printEndpoints(palette(false), endpoints, false)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = previousStdout
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 3 {
		t.Fatalf("printed %d lines, want header and two endpoints:\n%s", len(lines), output)
	}
	if headers := strings.Fields(lines[0]); len(headers) < 3 || headers[2] != "transport" {
		t.Fatalf("transport column missing from header: %q", lines[0])
	}
	if row := strings.Fields(lines[1]); len(row) < 3 || row[2] != "udp" {
		t.Fatalf("UDP row has wrong transport: %q", lines[1])
	}
	if row := strings.Fields(lines[2]); len(row) < 3 || row[2] != "fake-tcp" {
		t.Fatalf("fake-TCP row has wrong transport: %q", lines[2])
	}
}
