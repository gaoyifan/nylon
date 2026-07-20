//go:build !linux || android || (linux && !(amd64 || arm64))

package faketcp

type Manager struct{}

func Attach(uint16, []string) (*Manager, error) {
	return nil, ErrUnsupported
}

func (*Manager) Errors() <-chan error {
	return nil
}

func (*Manager) Close() error {
	return nil
}
