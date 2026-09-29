package seat

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Binding matches the seats.binding CHECK constraint.
type Binding string

const (
	// BindingProcess (v0.1): the Runner launches the harness for the seat.
	// There is no token for the model to see, leak, or lose.
	BindingProcess Binding = "process"
	// BindingConnection (v0.3+): an attached MCP session, authenticated by a
	// seat token that never enters the prompt.
	BindingConnection Binding = "connection"
)

// Status matches the seats.status CHECK constraint.
type Status string

const (
	StatusMinted  Status = "minted"
	StatusActive  Status = "active"
	StatusClosed  Status = "closed"  // finished normally
	StatusExpired Status = "expired" // lease ran out (autopsy)
	StatusRevoked Status = "revoked" // killed by core/human
)

// Minter identifies who is asking to mint a seat. Only the Ringleader seat
// or the human may (§8.B "Minting rule"); MintSeat rejects everyone else,
// including workers, adversaries, and judges trying to mint their own
// reviewers (the no-self-grading guarantee, §5.0).
type Minter struct {
	// IsHuman is true for a human-initiated mint (e.g. `arbiter run`, a
	// human reset). Exactly one of IsHuman or RingleaderSeatID is set.
	IsHuman bool
	// RingleaderSeatID is the minting Ringleader's own seat id.
	RingleaderSeatID string
}

func (m Minter) mintedBy() (string, error) {
	switch {
	case m.IsHuman && m.RingleaderSeatID != "":
		return "", errors.New("seat: minter cannot be both human and a ringleader seat")
	case m.IsHuman:
		return "human", nil
	case m.RingleaderSeatID != "":
		return m.RingleaderSeatID, nil
	default:
		return "", errors.New("seat: minting rule: only the ringleader seat or the human may mint seats")
	}
}

// verifyRingleader checks that seatID is a real, currently-live ringleader
// seat for prdID. mintedBy() only checks the shape of the Minter struct; a
// caller could otherwise pass an arbitrary string as RingleaderSeatID and
// have it accepted as the minting authority, defeating the minting rule
// (§8.B) entirely.
func verifyRingleader(ctx context.Context, db *sql.DB, seatID, prdID string) error {
	var role, status, seatPRD string
	err := db.QueryRowContext(ctx, `SELECT role, status, prd_id FROM seats WHERE id = ?`, seatID).
		Scan(&role, &status, &seatPRD)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("seat: minting rule: ringleader seat %s does not exist", seatID)
	}
	if err != nil {
		return fmt.Errorf("seat: verifying ringleader %s: %w", seatID, err)
	}
	if role != string(RoleRingleader) {
		return fmt.Errorf("seat: minting rule: %s is not a ringleader seat", seatID)
	}
	if status != string(StatusMinted) && status != string(StatusActive) {
		return fmt.Errorf("seat: minting rule: ringleader seat %s is %s, not minted or active", seatID, status)
	}
	if seatPRD != prdID {
		return fmt.Errorf("seat: minting rule: ringleader seat %s belongs to %s, not %s", seatID, seatPRD, prdID)
	}
	return nil
}

// verifyParentage checks that parentSeatID is either minterSeatID itself or
// one of its descendants in the seat tree (walking parent_seat_id upward).
// Only the Ringleader seat mints, but every minted seat must record its true
// place in the agent tree (§5.0); this stops a Ringleader from minting a
// seat and attributing it to a different, unrelated seat as parent.
func verifyParentage(ctx context.Context, db *sql.DB, minterSeatID, parentSeatID string) error {
	current := parentSeatID
	for depth := 0; depth < 64; depth++ { // bound: the agent tree is shallow; this guards against a corrupt cycle
		if current == minterSeatID {
			return nil
		}
		var parent sql.NullString
		err := db.QueryRowContext(ctx, `SELECT parent_seat_id FROM seats WHERE id = ?`, current).Scan(&parent)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("seat: minting rule: parent_seat_id %s does not exist", current)
		}
		if err != nil {
			return fmt.Errorf("seat: verifying parentage of %s: %w", parentSeatID, err)
		}
		if !parent.Valid {
			break
		}
		current = parent.String
	}
	return fmt.Errorf("seat: minting rule: parent_seat_id %s is not the minting ringleader %s or one of its descendants", parentSeatID, minterSeatID)
}

// MintRequest describes a seat to be minted.
type MintRequest struct {
	Role         Role
	PRDID        string
	TaskID       string // empty for the ringleader (unbound)
	ParentSeatID string // empty only for the ringleader
	CredentialID string
	Binding      Binding
}

// MintSeat inserts a new seat in status 'minted' and returns its id. The
// caller supplies by, identifying who is asking; only a human or an existing
// ringleader seat may mint (§8.B). The credential must be eligible for the
// requested role.
//
// Seat ids are readable paths plus a random suffix, e.g.
// "PRD-004/TASK-101/worker.2~7f3a" (§5.0), where the numeric part is a
// per-(task, role) sequence so a fix after a rejection can be told apart
// from the original attempt in the ledger even though it resumes the same
// seat's harness session.
func MintSeat(ctx context.Context, db *sql.DB, by Minter, req MintRequest) (string, error) {
	mintedBy, err := by.mintedBy()
	if err != nil {
		return "", err
	}
	if req.Role != RoleRingleader && req.ParentSeatID == "" {
		return "", fmt.Errorf("seat: %s seat requires a parent_seat_id", req.Role)
	}
	if req.Role == RoleRingleader && req.TaskID != "" {
		return "", errors.New("seat: ringleader seat must not be bound to a task")
	}
	if req.Role != RoleRingleader && req.TaskID == "" {
		return "", fmt.Errorf("seat: %s seat must be bound to a task", req.Role)
	}
	if req.Binding != BindingProcess && req.Binding != BindingConnection {
		return "", fmt.Errorf("seat: invalid binding %q", req.Binding)
	}
	if by.RingleaderSeatID != "" {
		if err := verifyRingleader(ctx, db, by.RingleaderSeatID, req.PRDID); err != nil {
			return "", err
		}
		if req.ParentSeatID != "" {
			if err := verifyParentage(ctx, db, by.RingleaderSeatID, req.ParentSeatID); err != nil {
				return "", err
			}
		}
	}

	cred, err := loadCredential(ctx, db, req.CredentialID)
	if err != nil {
		return "", err
	}
	if !cred.EligibleFor(req.Role) {
		return "", fmt.Errorf("seat: credential %s is not eligible for role %s", req.CredentialID, req.Role)
	}

	id, err := nextSeatID(ctx, db, req)
	if err != nil {
		return "", err
	}

	var taskID any
	if req.TaskID != "" {
		taskID = req.TaskID
	}
	var parentID any
	if req.ParentSeatID != "" {
		parentID = req.ParentSeatID
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO seats (id, role, task_id, prd_id, parent_seat_id, minted_by, credential_id, binding, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, string(req.Role), taskID, req.PRDID, parentID, mintedBy, req.CredentialID, string(req.Binding), string(StatusMinted),
	)
	if err != nil {
		return "", fmt.Errorf("seat: mint %s: %w", id, err)
	}
	return id, nil
}

func loadCredential(ctx context.Context, db *sql.DB, id string) (Credential, error) {
	var c Credential
	var harness, model, provenance, rolesJSON sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT id, kind, harness, model, model_provenance, eligible_roles
		FROM credentials WHERE id = ?`, id,
	).Scan(&c.ID, &c.Kind, &harness, &model, &provenance, &rolesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, fmt.Errorf("seat: credential %s not found", id)
	}
	if err != nil {
		return Credential{}, fmt.Errorf("seat: load credential %s: %w", id, err)
	}
	c.Harness, c.Model, c.ModelProvenance = harness.String, model.String, ModelProvenance(provenance.String)
	c.EligibleRoles = decodeRoles(rolesJSON.String)
	return c, nil
}

func decodeRoles(js string) []Role {
	if js == "" {
		return nil
	}
	var raw []string
	if err := json.Unmarshal([]byte(js), &raw); err != nil {
		return nil
	}
	roles := make([]Role, len(raw))
	for i, r := range raw {
		roles[i] = Role(r)
	}
	return roles
}

// nextSeatID picks the next per-(task-or-prd, role) sequence number and
// appends a random hex suffix.
func nextSeatID(ctx context.Context, db *sql.DB, req MintRequest) (string, error) {
	var scope, prefix string
	if req.Role == RoleRingleader {
		scope = req.PRDID
		prefix = fmt.Sprintf("%s/ringleader.", req.PRDID)
	} else {
		scope = req.TaskID
		prefix = fmt.Sprintf("%s/%s.", req.TaskID, req.Role)
	}
	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM seats WHERE role = ? AND COALESCE(task_id, prd_id) = ?`,
		string(req.Role), scope,
	).Scan(&count)
	if err != nil {
		return "", fmt.Errorf("seat: counting existing %s seats: %w", req.Role, err)
	}
	suffix, err := randomSuffix()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%d~%s", prefix, count+1, suffix), nil
}

func randomSuffix() (string, error) {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("seat: generating id suffix: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// validTransitions enumerates the seat status FSM (§8.B): minted -> active
// -> {closed, expired, revoked}, with revoked also reachable directly from
// minted (a mint can be killed by core/human before its first invocation).
var validTransitions = map[Status][]Status{
	StatusMinted:  {StatusActive, StatusRevoked},
	StatusActive:  {StatusClosed, StatusExpired, StatusRevoked},
	StatusClosed:  {},
	StatusExpired: {},
	StatusRevoked: {},
}

// Transition moves a seat to a new status, enforcing the FSM in validTransitions.
func Transition(ctx context.Context, db *sql.DB, seatID string, to Status) error {
	var current Status
	err := db.QueryRowContext(ctx, `SELECT status FROM seats WHERE id = ?`, seatID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("seat: %s not found", seatID)
	}
	if err != nil {
		return fmt.Errorf("seat: loading status of %s: %w", seatID, err)
	}
	allowed := validTransitions[current]
	valid := false
	for _, s := range allowed {
		if s == to {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("seat: %s: invalid transition %s -> %s", seatID, current, to)
	}
	// The WHERE clause re-checks status = current so a concurrent transition
	// between the read above and this write can't be silently overwritten;
	// RowsAffected == 0 means someone else moved the seat first.
	res, err := db.ExecContext(ctx, `UPDATE seats SET status = ? WHERE id = ? AND status = ?`,
		string(to), seatID, string(current))
	if err != nil {
		return fmt.Errorf("seat: transitioning %s to %s: %w", seatID, to, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("seat: transitioning %s to %s: %w", seatID, to, err)
	}
	if n == 0 {
		return fmt.Errorf("seat: %s: status changed concurrently, retry", seatID)
	}
	return nil
}

// CloseTaskSeats closes every non-terminal seat bound to a task. Called when
// the task reaches 'done' or 'failed' (§8.B: "Seats become closed when their
// task reaches done or failed").
func CloseTaskSeats(ctx context.Context, db *sql.DB, taskID string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE seats SET status = ?
		WHERE task_id = ? AND status IN (?, ?)`,
		string(StatusClosed), taskID, string(StatusMinted), string(StatusActive),
	)
	if err != nil {
		return fmt.Errorf("seat: closing seats for task %s: %w", taskID, err)
	}
	return nil
}
