//go:build !linux || android || (linux && !(amd64 || arm64))

package conn

func fakeTCPPlatformSupported() bool { return false }

func fakeTCPListenControl(fake bool) controlFn { return nil }
