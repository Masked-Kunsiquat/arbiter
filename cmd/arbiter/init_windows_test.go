//go:build windows

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDevDriveRecommendation(t *testing.T) {
	dir := t.TempDir()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	printDevDriveRecommendation(dir)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "Dev Drive (ReFS)") {
		t.Errorf("output = %q, want mention of Dev Drive (ReFS)", out)
	}
}
