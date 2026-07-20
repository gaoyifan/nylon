//go:build linux && !android

package faketcp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -tags linux,!android -target bpfel transformer transformer.c
