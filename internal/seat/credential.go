// Package seat implements Arbiter's agent-identity domain logic: credentials,
// seats, and invocations (spec §5.0, §8.B), on top of the state.db schema
// from internal/db.
//
// Identity never passes through the model (§8.B): a seat is bound to a
// process (v0.1) or a connection (v0.3+), never a token the harness could
// leak, forget, or mistype. This package is the only place that mints seats
// or transitions their status; callers pass the role of whoever is asking
// (§5.0's "only the Ringleader seat or the human can mint seats"), and
// MintSeat rejects anyone else.
package seat

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// CredentialKind matches the credentials.kind CHECK constraint.
type CredentialKind string

const (
	KindHuman CredentialKind = "human"
	KindAgent CredentialKind = "agent"
)

// ModelProvenance matches credentials.model_provenance.
type ModelProvenance string

const (
	// ProvenanceLaunched means Arbiter set --model itself.
	ProvenanceLaunched ModelProvenance = "launched"
	// ProvenanceClaimed means the model name was self-reported by an attached session (v0.3+).
	ProvenanceClaimed ModelProvenance = "claimed"
)

// Role matches the seats.role CHECK constraint.
type Role string

const (
	RoleRingleader Role = "ringleader"
	RoleWorker     Role = "worker"
	RoleAdversary  Role = "adversary"
	RoleJudge      Role = "judge"
)

// Credential describes what kind of agent a seat belongs to. For agents
// Arbiter launches this is a descriptor, not a secret (§8.B): SecretHash is
// only set for attached (v0.3+) sessions.
type Credential struct {
	ID              string
	Kind            CredentialKind
	Harness         string // 'claude-code' | 'cursor' | 'aider' | ...; empty for human
	Model           string
	ModelProvenance ModelProvenance
	EligibleRoles   []Role
	SecretHash      string // only for attached (not launched) sessions
}

// RegisterCredential inserts a credential row. EligibleRoles is stored as a
// JSON array per the schema; it is empty (not present) for a human credential.
func RegisterCredential(ctx context.Context, db *sql.DB, c Credential) error {
	if c.ID == "" {
		return errors.New("seat: credential id is required")
	}
	if c.Kind != KindHuman && c.Kind != KindAgent {
		return fmt.Errorf("seat: invalid credential kind %q", c.Kind)
	}
	roles, err := json.Marshal(c.EligibleRoles)
	if err != nil {
		return fmt.Errorf("seat: marshal eligible_roles: %w", err)
	}
	var provenance any
	if c.ModelProvenance != "" {
		provenance = string(c.ModelProvenance)
	}
	var secretHash any
	if c.SecretHash != "" {
		secretHash = c.SecretHash
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO credentials (id, kind, harness, model, model_provenance, eligible_roles, secret_hash)
		VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?)`,
		c.ID, string(c.Kind), c.Harness, c.Model, provenance, string(roles), secretHash,
	)
	if err != nil {
		return fmt.Errorf("seat: register credential %s: %w", c.ID, err)
	}
	return nil
}

// EligibleFor reports whether the credential may be seated in role r.
func (c Credential) EligibleFor(r Role) bool {
	for _, er := range c.EligibleRoles {
		if er == r {
			return true
		}
	}
	return false
}
