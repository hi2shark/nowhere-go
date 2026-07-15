package wire

import "errors"

var (
	ErrInvalidTarget      = errors.New("nowhere: invalid target address")
	ErrInvalidFrame       = errors.New("nowhere: invalid frame")
	ErrUnsupportedVersion = errors.New("nowhere: unsupported frame version")
	ErrPaddingTooLarge    = errors.New("nowhere: padding too large")
)
