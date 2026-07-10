package server

// Logger is an optional diagnostic sink. Hosts inject their own logger.
type Logger interface {
	Infof(format string, args ...any)
	Debugf(format string, args ...any)
	Errorf(format string, args ...any)
}

// NopLogger discards all log output.
type NopLogger struct{}

func (NopLogger) Infof(string, ...any)  {}
func (NopLogger) Debugf(string, ...any) {}
func (NopLogger) Errorf(string, ...any) {}

func resolveLogger(l Logger) Logger {
	if l == nil {
		return NopLogger{}
	}
	return l
}
