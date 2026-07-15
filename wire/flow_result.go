package wire

import (
	"errors"
	"fmt"
	"io"
)

const (
	FlowResultMagic   byte = 0xf2
	FlowResultVersion byte = 1
	FlowResultLen          = 4
)

type FlowStatus uint8

const (
	FlowStatusReady  FlowStatus = 1
	FlowStatusReject FlowStatus = 2
)

type FlowErrorCode uint8

const (
	FlowErrorCodeInvalidRequest   FlowErrorCode = 1
	FlowErrorCodeMetadataConflict FlowErrorCode = 2
	FlowErrorCodePairTimeout      FlowErrorCode = 3
	FlowErrorCodeFlowLimit        FlowErrorCode = 4
	FlowErrorCodeDialFailed       FlowErrorCode = 5
	FlowErrorCodeSessionReplaced  FlowErrorCode = 6
	FlowErrorCodeInternalError    FlowErrorCode = 7
)

type FlowResult struct {
	Status FlowStatus
	Code   FlowErrorCode
}

type FlowError struct {
	Code   FlowErrorCode
	Remote bool
	Cause  error
}

var ErrInvalidFlowResult = errors.New("nowhere: invalid flow result")

func (e *FlowError) Error() string {
	if e == nil {
		return "<nil>"
	}
	source := "local"
	if e.Remote {
		source = "remote"
	}
	if e.Cause != nil {
		return fmt.Sprintf("nowhere: %s flow error %s: %v", source, e.Code, e.Cause)
	}
	return fmt.Sprintf("nowhere: %s flow error %s", source, e.Code)
}

func (e *FlowError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (code FlowErrorCode) String() string {
	switch code {
	case FlowErrorCodeInvalidRequest:
		return "invalid_request"
	case FlowErrorCodeMetadataConflict:
		return "metadata_conflict"
	case FlowErrorCodePairTimeout:
		return "pair_timeout"
	case FlowErrorCodeFlowLimit:
		return "flow_limit"
	case FlowErrorCodeDialFailed:
		return "dial_failed"
	case FlowErrorCodeSessionReplaced:
		return "session_replaced"
	case FlowErrorCodeInternalError:
		return "internal_error"
	default:
		return fmt.Sprintf("code_%d", code)
	}
}

func WriteFlowResult(result FlowResult) ([FlowResultLen]byte, error) {
	if err := validateFlowResult(result); err != nil {
		return [FlowResultLen]byte{}, err
	}
	return [FlowResultLen]byte{
		FlowResultMagic,
		FlowResultVersion,
		byte(result.Status),
		byte(result.Code),
	}, nil
}

func ReadFlowResult(r io.Reader) (FlowResult, error) {
	var frame [FlowResultLen]byte
	if _, err := io.ReadFull(r, frame[:]); err != nil {
		return FlowResult{}, err
	}
	if frame[0] != FlowResultMagic || frame[1] != FlowResultVersion {
		return FlowResult{}, ErrInvalidFlowResult
	}
	result := FlowResult{Status: FlowStatus(frame[2]), Code: FlowErrorCode(frame[3])}
	if err := validateFlowResult(result); err != nil {
		return FlowResult{}, ErrInvalidFlowResult
	}
	return result, nil
}

func (result FlowResult) Err(remote bool) error {
	if err := validateFlowResult(result); err != nil {
		return err
	}
	if result.Status == FlowStatusReady {
		return nil
	}
	return &FlowError{Code: result.Code, Remote: remote}
}

func validateFlowResult(result FlowResult) error {
	switch result.Status {
	case FlowStatusReady:
		if result.Code != 0 {
			return ErrInvalidFlowResult
		}
	case FlowStatusReject:
		if !validFlowErrorCode(result.Code) {
			return ErrInvalidFlowResult
		}
	default:
		return ErrInvalidFlowResult
	}
	return nil
}

func validFlowErrorCode(code FlowErrorCode) bool {
	return code >= FlowErrorCodeInvalidRequest && code <= FlowErrorCodeInternalError
}
