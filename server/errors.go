package server

import "errors"

var (
	// ErrInvalidConfig identifies rejected configuration input.
	ErrInvalidConfig = errors.New("nowhere: invalid server config")
	// ErrInvalidHandler identifies an unusable or nil handler dependency.
	ErrInvalidHandler = errors.New("nowhere: invalid handler")
	// ErrPairTimeout identifies an asymmetric half that was not paired in time.
	ErrPairTimeout = errors.New("nowhere: flow pair timeout")
	// ErrPairLimit identifies an exhausted pending-pair budget.
	ErrPairLimit = errors.New("nowhere: pending flow pair limit reached")
	// ErrCarrierMismatch identifies inconsistent metadata between flow halves.
	ErrCarrierMismatch = errors.New("nowhere: flow carrier metadata mismatch")
	// ErrDuplicateHalf identifies two halves claiming the same role.
	ErrDuplicateHalf = errors.New("nowhere: duplicate flow half")
	// ErrSessionLimit identifies an exhausted active-session budget.
	ErrSessionLimit = errors.New("nowhere: active session limit reached")
	// ErrUpstreamNotConfigured identifies a missing flow destination.
	ErrUpstreamNotConfigured = errors.New("nowhere: upstream not configured")
	// ErrClosed identifies operations attempted after manager shutdown.
	ErrClosed = errors.New("nowhere: manager closed")
	// ErrQUICNotConfigured identifies an enabled UDP carrier without a listener.
	ErrQUICNotConfigured = errors.New("nowhere: QUIC enabled but no QuicListener injected")
	// ErrTLSNotConfigured identifies an enabled TCP carrier without a handshaker.
	ErrTLSNotConfigured = errors.New("nowhere: TCP enabled but no TLS handshaker configured")
	// ErrUnsupportedFlow identifies a valid frame unsupported by this endpoint.
	ErrUnsupportedFlow = errors.New("nowhere: unsupported flow")
)
