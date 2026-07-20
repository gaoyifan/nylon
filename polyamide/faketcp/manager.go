package faketcp

import "errors"

var ErrUnsupported = errors.New("fake TCP requires Linux 6.6 or newer on amd64 or arm64")
