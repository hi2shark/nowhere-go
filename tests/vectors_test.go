package tests_test

import (
	"testing"

	"github.com/hi2shark/nowhere-go/internal/vectors"
)

func TestHarnessVectors(t *testing.T) {
	dir, err := vectors.Dir()
	if err != nil {
		t.Skipf("vectors unavailable: %v", err)
	}
	n, err := vectors.CheckDir(dir)
	if err != nil {
		t.Fatalf("CheckDir(%s): %v", dir, err)
	}
	if n == 0 {
		t.Fatal("no vector cases checked")
	}
	t.Logf("checked %d vector cases from %s", n, dir)
}
