package worktree

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CacheConfig specifies the directories used for shared tool caches across slots
// and per-slot target directories (spec §7: "Shared caches: pnpm store,
// GOCACHE, sccache; per-slot CARGO_TARGET_DIR").
type CacheConfig struct {
	GoCacheDir     string
	SccacheDir     string
	PnpmStoreDir   string
	PnpmHome       string
	CargoTargetDir string
}

// DefaultCacheConfig returns the standard cache paths for a worktree slot.
// Shared caches (Go, sccache, pnpm) reside under .arbiter/cache/ so they are
// shared across slots and task runs. CARGO_TARGET_DIR is segregated per slot
// to prevent cargo build lock contention.
func DefaultCacheConfig(arbiterDir string, slotDir string, slotIndex int) CacheConfig {
	cacheBase := filepath.Join(arbiterDir, "cache")
	return CacheConfig{
		GoCacheDir:     filepath.Join(cacheBase, "go-build"),
		SccacheDir:     filepath.Join(cacheBase, "sccache"),
		PnpmStoreDir:   filepath.Join(cacheBase, "pnpm-store"),
		PnpmHome:       filepath.Join(cacheBase, "pnpm"),
		CargoTargetDir: filepath.Join(cacheBase, "cargo-target", fmt.Sprintf("slot-%d", slotIndex)),
	}
}

// EnsureDirs creates all configured cache directories on disk.
func (c CacheConfig) EnsureDirs() error {
	dirs := []string{c.GoCacheDir, c.SccacheDir, c.PnpmStoreDir, c.PnpmHome, c.CargoTargetDir}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("worktree: creating cache dir %s: %w", d, err)
		}
	}
	return nil
}

// Env returns the environment variable assignments that configure toolchains
// to use the shared caches and per-slot target directory.
func (c CacheConfig) Env() []string {
	var env []string
	if c.GoCacheDir != "" {
		env = append(env, "GOCACHE="+c.GoCacheDir)
	}
	if c.SccacheDir != "" {
		env = append(env, "SCCACHE_DIR="+c.SccacheDir)
	}
	if c.PnpmStoreDir != "" {
		env = append(env, "PNPM_STORE_DIR="+c.PnpmStoreDir, "npm_config_store_dir="+c.PnpmStoreDir)
	}
	if c.PnpmHome != "" {
		env = append(env, "PNPM_HOME="+c.PnpmHome)
	}
	if c.CargoTargetDir != "" {
		env = append(env, "CARGO_TARGET_DIR="+c.CargoTargetDir)
	}
	return env
}

// ApplyEnv overlays extra variables onto baseEnv, updating existing keys
// (case-insensitively on Windows, case-sensitively on POSIX).
func ApplyEnv(baseEnv []string, extra []string) []string {
	envMap := make(map[string]string, len(baseEnv)+len(extra))
	// canonicalKey tracks the canonical case used in envMap.
	canonicalKey := func(k string) string {
		if runtime.GOOS == "windows" {
			return strings.ToUpper(k)
		}
		return k
	}

	rawKeys := make(map[string]string, len(baseEnv))
	for _, entry := range baseEnv {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		ck := canonicalKey(k)
		envMap[ck] = v
		rawKeys[ck] = k
	}

	for _, entry := range extra {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		ck := canonicalKey(k)
		envMap[ck] = v
		rawKeys[ck] = k
	}

	res := make([]string, 0, len(envMap))
	for ck, v := range envMap {
		k := rawKeys[ck]
		res = append(res, k+"="+v)
	}
	return res
}
