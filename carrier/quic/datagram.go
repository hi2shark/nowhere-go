package quic

import "fmt"

// DatagramTooLargeError is returned when a DATAGRAM exceeds the current path limit.
type DatagramTooLargeError struct {
	MaxDatagramSize int
	Cause           error
}

func (e *DatagramTooLargeError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("nowhere: datagram too large (max %d): %v", e.MaxDatagramSize, e.Cause)
}

func (e *DatagramTooLargeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}
