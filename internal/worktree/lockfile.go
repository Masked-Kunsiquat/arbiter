package worktree

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// SlotMetadata tracks persisted state for a warm worktree slot. It is stored
// under .arbiter/worktrees/slot-<N>.meta.json (outside the worktree slot itself)
// so that git clean -fdx operations do not wipe it.
type SlotMetadata struct {
	SlotIndex       int       `json:"slot_index"`
	LastInstallHash string    `json:"last_install_hash"`
	LastInstalledAt time.Time `json:"last_installed_at,omitempty"`
	LastBaseCommit  string    `json:"last_base_commit,omitempty"`
}

// MetadataPath returns the path to the metadata JSON file for slotIndex.
func MetadataPath(arbiterDir string, slotIndex int) string {
	return filepath.Join(arbiterDir, "worktrees", fmt.Sprintf("slot-%d.meta.json", slotIndex))
}

// LoadMetadata reads the slot metadata from disk. If the metadata file does
// not exist yet, a default instance with an empty LastInstallHash is returned.
func LoadMetadata(arbiterDir string, slotIndex int) (*SlotMetadata, error) {
	p := MetadataPath(arbiterDir, slotIndex)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &SlotMetadata{
				SlotIndex: slotIndex,
			}, nil
		}
		return nil, fmt.Errorf("worktree: loading metadata from %s: %w", p, err)
	}

	var meta SlotMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("worktree: parsing metadata %s: %w", p, err)
	}
	return &meta, nil
}

// SaveMetadata writes slot metadata to disk atomically.
func SaveMetadata(arbiterDir string, meta *SlotMetadata) error {
	dir := filepath.Join(arbiterDir, "worktrees")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("worktree: creating worktrees dir: %w", err)
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("worktree: encoding metadata: %w", err)
	}
	data = append(data, '\n')

	target := MetadataPath(arbiterDir, meta.SlotIndex)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("worktree: writing tmp metadata %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("worktree: replacing metadata %s: %w", target, err)
	}
	return nil
}

// ComputeLockfileHash computes a deterministic SHA-256 hash of all specified
// lockfiles in slotDir. If no lockfiles are specified or exist, a deterministic
// empty hash is returned.
func ComputeLockfileHash(slotDir string, lockfiles []string) (string, error) {
	if len(lockfiles) == 0 {
		h := sha256.Sum256(nil)
		return hex.EncodeToString(h[:]), nil
	}

	sorted := slices.Clone(lockfiles)
	slices.Sort(sorted)

	hasher := sha256.New()
	found := false

	for _, name := range sorted {
		fullPath := filepath.Join(slotDir, name)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				hasher.Write([]byte(name + ":absent\x00"))
				continue
			}
			return "", fmt.Errorf("worktree: reading lockfile %s: %w", name, err)
		}
		found = true
		hasher.Write([]byte(name + ":present\x00"))
		hasher.Write(data)
		hasher.Write([]byte{0})
	}

	if !found {
		h := sha256.Sum256(nil)
		return hex.EncodeToString(h[:]), nil
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// ShouldReinstall determines whether dependency installation is required (spec §7:
// "Dependencies reinstall only when the lockfile hash differs from the slot's
// last install, or when the unseen-state check (§5.3) finds the keep-list dirs
// changed during an agent run").
func ShouldReinstall(currentHash, lastHash string, unseenChanges bool, force bool) bool {
	if force {
		return true
	}
	if unseenChanges {
		return true
	}
	if lastHash == "" {
		return true
	}
	return currentHash != lastHash
}
