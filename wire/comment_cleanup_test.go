package wire

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRequestSourceDoesNotDocumentRemovedUOTSetupAPI(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(current), "request.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(raw, []byte("// ReadUOTSetupTarget")) {
		t.Fatal("request.go still documents removed ReadUOTSetupTarget")
	}
}
