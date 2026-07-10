package carrier

// Logger is an optional diagnostic sink injected by host adapters.
// Implementations may no-op; core never imports host log packages.
type Logger interface {
	Debugf(format string, args ...any)
	Warnf(format string, args ...any)
}

// NopLogger discards all log output.
type NopLogger struct{}

func (NopLogger) Debugf(string, ...any) {}
func (NopLogger) Warnf(string, ...any)  {}
