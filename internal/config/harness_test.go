package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
)

func TestResolveHarnessCommand_Empty(t *testing.T) {
	if _, err := config.ResolveHarnessCommand(""); err == nil {
		t.Fatal("ResolveHarnessCommand(\"\"): want error, got nil")
	}
	if _, err := config.ResolveHarnessCommand("   "); err == nil {
		t.Fatal("ResolveHarnessCommand(whitespace): want error, got nil")
	}
}

func TestResolveHarnessCommand_NotFound(t *testing.T) {
	if _, err := config.ResolveHarnessCommand("definitely-not-a-real-binary-xyz"); err == nil {
		t.Fatal("ResolveHarnessCommand(missing binary): want error, got nil")
	}
}

// TestResolveHarnessCommand_RejectsNonExe verifies that on Windows any
// resolved extension other than .exe is rejected. We test with .cmd (a common
// shim) and .bat; both must fail with ErrHarnessShim.
func TestResolveHarnessCommand_RejectsNonExe(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("non-.exe rejection only applies on windows")
	}

	for _, ext := range []string{".cmd", ".bat"} {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			name := "fake-harness" + ext
			if err := os.WriteFile(filepath.Join(dir, name), []byte("@echo off\r\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

			_, err := config.ResolveHarnessCommand("fake-harness")
			if err == nil {
				t.Fatalf("ResolveHarnessCommand(%s): want error, got nil", ext)
			}
			if !errors.Is(err, config.ErrHarnessShim) {
				t.Errorf("ResolveHarnessCommand(%s): got %v, want errors.Is(ErrHarnessShim)", ext, err)
			}
		})
	}
}

func TestResolveHarnessCommand_AcceptsNativeExe(t *testing.T) {
	dir := t.TempDir()
	var name, content string
	if runtime.GOOS == "windows" {
		name, content = "fake-native.exe", "not a real PE, just needs to be a .exe"
	} else {
		name, content = "fake-native", "#!/bin/sh\nexit 0\n"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	resolved, err := config.ResolveHarnessCommand("fake-native")
	if err != nil {
		t.Fatalf("ResolveHarnessCommand(native exe): %v", err)
	}
	if resolved == "" {
		t.Error("resolved path is empty")
	}
}
