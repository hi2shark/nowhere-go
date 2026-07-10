package wire

import (
	"errors"
	"io"
)

var (
	ErrInvalidTarget       = errors.New("nowhere: invalid target address")
	ErrInvalidFrame        = errors.New("nowhere: invalid frame")
	ErrUnsupportedVersion  = errors.New("nowhere: unsupported frame version")
	ErrPaddingTooLarge     = errors.New("nowhere: uot payload too large")
	ErrDestinationTooLarge = errors.New("nowhere: destination too large for datagram")

	errUOTEOF = io.EOF
)
