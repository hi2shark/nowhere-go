package quic

import "github.com/hi2shark/nowhere-go/wire"

var _ func(Backend, wire.SessionID) = Backend.SetSessionID
