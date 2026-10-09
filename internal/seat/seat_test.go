package seat_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/db"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	adb, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { adb.Close() })
	return adb.SQLDB()
}

func seedPRDAndTask(t *testing.T, raw *sql.DB, prdID, taskID string) {
	t.Helper()
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
		VALUES (?, 'Test', 'p.md', 'h', 'locked', 'main')`, prdID)
	if err != nil {
		t.Fatalf("seed prd: %v", err)
	}
	if taskID == "" {
		return
	}
	_, err = raw.ExecContext(context.Background(), `
		INSERT INTO tasks (id, prd_id, title, intent, status)
		VALUES (?, ?, 'Task', 'intent', 'ready')`, taskID, prdID)
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}
}

func registerAgentCred(t *testing.T, raw *sql.DB, id string, roles ...seat.Role) {
	t.Helper()
	err := seat.RegisterCredential(context.Background(), raw, seat.Credential{
		ID:              id,
		Kind:            seat.KindAgent,
		Harness:         "claude-code",
		Model:           "claude-opus-5-5",
		ModelProvenance: seat.ProvenanceLaunched,
		EligibleRoles:   roles,
	})
	if err != nil {
		t.Fatalf("register credential: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Credentials
// ─────────────────────────────────────────────────────────────────────────────

func TestRegisterCredential_EligibleFor(t *testing.T) {
	raw := openDB(t)
	registerAgentCred(t, raw, "cred:claude-code/opus", seat.RoleRingleader, seat.RoleWorker)

	var rolesJSON string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT eligible_roles FROM credentials WHERE id = 'cred:claude-code/opus'`).Scan(&rolesJSON); err != nil {
		t.Fatalf("query: %v", err)
	}
	if rolesJSON == "" || rolesJSON == "[]" {
		t.Fatalf("eligible_roles not persisted, got %q", rolesJSON)
	}
}

func TestRegisterCredential_InvalidKind(t *testing.T) {
	raw := openDB(t)
	err := seat.RegisterCredential(context.Background(), raw, seat.Credential{
		ID:   "cred:x",
		Kind: seat.CredentialKind("robot"),
	})
	if err == nil {
		t.Fatal("expected error for invalid kind, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Minting rule: only human or an existing ringleader seat may mint
// ─────────────────────────────────────────────────────────────────────────────

func TestMintSeat_HumanMintsRingleader(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "")
	registerAgentCred(t, raw, "cred:rl", seat.RoleRingleader)

	id, err := seat.MintSeat(context.Background(), raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role:         seat.RoleRingleader,
		PRDID:        "PRD-001",
		CredentialID: "cred:rl",
		Binding:      seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("MintSeat: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty seat id")
	}
}

func TestMintSeat_RingleaderMintsWorker(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	registerAgentCred(t, raw, "cred:rl", seat.RoleRingleader)
	registerAgentCred(t, raw, "cred:worker", seat.RoleWorker)

	rlID, err := seat.MintSeat(context.Background(), raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role:         seat.RoleRingleader,
		PRDID:        "PRD-001",
		CredentialID: "cred:rl",
		Binding:      seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint ringleader: %v", err)
	}

	workerID, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role:         seat.RoleWorker,
		PRDID:        "PRD-001",
		TaskID:       "TASK-001",
		ParentSeatID: rlID,
		CredentialID: "cred:worker",
		Binding:      seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint worker: %v", err)
	}
	if workerID == "" {
		t.Fatal("expected non-empty worker seat id")
	}
}

func TestMintSeat_RejectsNeitherHumanNorRingleader(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	registerAgentCred(t, raw, "cred:worker", seat.RoleWorker)

	_, err := seat.MintSeat(context.Background(), raw, seat.Minter{}, seat.MintRequest{
		Role:         seat.RoleWorker,
		PRDID:        "PRD-001",
		TaskID:       "TASK-001",
		ParentSeatID: "some-parent",
		CredentialID: "cred:worker",
		Binding:      seat.BindingProcess,
	})
	if err == nil {
		t.Fatal("expected minting rule violation, got nil")
	}
}

func TestMintSeat_RejectsIneligibleCredential(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	registerAgentCred(t, raw, "cred:worker-only", seat.RoleWorker)

	_, err := seat.MintSeat(context.Background(), raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role:         seat.RoleJudge,
		PRDID:        "PRD-001",
		TaskID:       "TASK-001",
		ParentSeatID: "PRD-001/ringleader.1~aaaa",
		CredentialID: "cred:worker-only",
		Binding:      seat.BindingProcess,
	})
	if err == nil {
		t.Fatal("expected ineligible-role error, got nil")
	}
}

func TestMintSeat_RingleaderMustNotBindTask(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	registerAgentCred(t, raw, "cred:rl", seat.RoleRingleader)

	_, err := seat.MintSeat(context.Background(), raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role:         seat.RoleRingleader,
		PRDID:        "PRD-001",
		TaskID:       "TASK-001",
		CredentialID: "cred:rl",
		Binding:      seat.BindingProcess,
	})
	if err == nil {
		t.Fatal("expected error for task-bound ringleader, got nil")
	}
}

func TestMintSeat_NonRingleaderRequiresTask(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "")
	registerAgentCred(t, raw, "cred:w", seat.RoleWorker)

	_, err := seat.MintSeat(context.Background(), raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role:         seat.RoleWorker,
		PRDID:        "PRD-001",
		ParentSeatID: "PRD-001/ringleader.1~aaaa",
		CredentialID: "cred:w",
		Binding:      seat.BindingProcess,
	})
	if err == nil {
		t.Fatal("expected error for unbound worker, got nil")
	}
}

func TestMintSeat_SequenceAndSuffix(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	rlID := mintRingleaderSeat(t, raw, "PRD-001")
	registerAgentCred(t, raw, "cred:w", seat.RoleWorker)

	id1, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: rlID, CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint 1: %v", err)
	}

	// Close it so a fresh seat scenario (human reset) makes sense, then mint again.
	if err := seat.Transition(context.Background(), raw, id1, seat.StatusRevoked); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	id2, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: rlID, CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected distinct seat ids, got %q twice", id1)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Seat status FSM
// ─────────────────────────────────────────────────────────────────────────────

// mintRingleaderSeat mints a real ringleader seat so callers have a valid
// parent_seat_id to reference (seats.parent_seat_id has an FK to seats.id).
func mintRingleaderSeat(t *testing.T, raw *sql.DB, prdID string) string {
	t.Helper()
	registerAgentCred(t, raw, "cred:rl-"+prdID, seat.RoleRingleader)
	id, err := seat.MintSeat(context.Background(), raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role: seat.RoleRingleader, PRDID: prdID, CredentialID: "cred:rl-" + prdID, Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint ringleader: %v", err)
	}
	return id
}

func mintTestSeat(t *testing.T, raw *sql.DB) string {
	t.Helper()
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	rlID := mintRingleaderSeat(t, raw, "PRD-001")
	registerAgentCred(t, raw, "cred:w", seat.RoleWorker)
	id, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: rlID, CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return id
}

func TestTransition_MintedToActive(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	if err := seat.Transition(context.Background(), raw, id, seat.StatusActive); err != nil {
		t.Fatalf("Transition: %v", err)
	}
}

func TestTransition_ActiveToClosed(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusActive))
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusClosed))
}

func TestTransition_RejectsFromTerminal(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusActive))
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusClosed))

	if err := seat.Transition(context.Background(), raw, id, seat.StatusActive); err == nil {
		t.Fatal("expected error transitioning out of closed, got nil")
	}
}

func TestTransition_RejectsSkippingToExpiredFromMinted(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	// minted -> expired is not a listed transition (only via active).
	if err := seat.Transition(context.Background(), raw, id, seat.StatusExpired); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestTransition_MintedToRevoked(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	if err := seat.Transition(context.Background(), raw, id, seat.StatusRevoked); err != nil {
		t.Fatalf("Transition: %v", err)
	}
}

func TestTransition_UnknownSeat(t *testing.T) {
	raw := openDB(t)
	if err := seat.Transition(context.Background(), raw, "nope", seat.StatusActive); err == nil {
		t.Fatal("expected error for unknown seat, got nil")
	}
}

func TestCloseTaskSeats(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusActive))

	if err := seat.CloseTaskSeats(context.Background(), raw, "TASK-001"); err != nil {
		t.Fatalf("CloseTaskSeats: %v", err)
	}
	var status string
	if err := raw.QueryRowContext(context.Background(), `SELECT status FROM seats WHERE id = ?`, id).Scan(&status); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != string(seat.StatusClosed) {
		t.Errorf("status = %q, want %q", status, seat.StatusClosed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Invocations
// ─────────────────────────────────────────────────────────────────────────────

func TestStartInvocation_ActivatesMintedSeat(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)

	invID, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID:         id,
		TaskID:         "TASK-001",
		Purpose:        seat.PurposeImplement,
		PID:            1234,
		LeaseExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("StartInvocation: %v", err)
	}
	if invID == "" {
		t.Fatal("expected non-empty invocation id")
	}

	var status string
	if err := raw.QueryRowContext(context.Background(), `SELECT status FROM seats WHERE id = ?`, id).Scan(&status); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != string(seat.StatusActive) {
		t.Errorf("seat status = %q, want active", status)
	}
}

func TestStartInvocation_RejectsClosedSeat(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusActive))
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusClosed))

	_, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID: id, TaskID: "TASK-001", Purpose: seat.PurposeFix,
	})
	if err == nil {
		t.Fatal("expected error starting invocation on closed seat, got nil")
	}
}

func TestEndInvocation_RecordsCost(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	invID, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID: id, TaskID: "TASK-001", Purpose: seat.PurposeImplement,
	})
	if err != nil {
		t.Fatalf("StartInvocation: %v", err)
	}

	cost := 1.23
	if err := seat.EndInvocation(context.Background(), raw, seat.EndInvocationRequest{
		InvocationID: invID,
		ExitReason:   seat.ExitOK,
		CostUSD:      &cost,
	}); err != nil {
		t.Fatalf("EndInvocation: %v", err)
	}

	var gotCost float64
	var exitReason string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT cost_usd, exit_reason FROM invocations WHERE id = ?`, invID).Scan(&gotCost, &exitReason); err != nil {
		t.Fatalf("query: %v", err)
	}
	if gotCost != cost || exitReason != string(seat.ExitOK) {
		t.Errorf("got cost=%v exit_reason=%v, want cost=%v exit_reason=%v", gotCost, exitReason, cost, seat.ExitOK)
	}
}

func TestEndInvocation_NilCostForKilled(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	invID, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID: id, TaskID: "TASK-001", Purpose: seat.PurposeImplement,
	})
	if err != nil {
		t.Fatalf("StartInvocation: %v", err)
	}

	if err := seat.EndInvocation(context.Background(), raw, seat.EndInvocationRequest{
		InvocationID: invID,
		ExitReason:   seat.ExitKilled,
	}); err != nil {
		t.Fatalf("EndInvocation: %v", err)
	}

	var gotCost sql.NullFloat64
	if err := raw.QueryRowContext(context.Background(),
		`SELECT cost_usd FROM invocations WHERE id = ?`, invID).Scan(&gotCost); err != nil {
		t.Fatalf("query: %v", err)
	}
	if gotCost.Valid {
		t.Errorf("expected NULL cost_usd for killed invocation, got %v", gotCost.Float64)
	}
}

func TestEndInvocation_InvalidExitReason(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	invID, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID: id, TaskID: "TASK-001", Purpose: seat.PurposeImplement,
	})
	if err != nil {
		t.Fatalf("StartInvocation: %v", err)
	}

	err = seat.EndInvocation(context.Background(), raw, seat.EndInvocationRequest{
		InvocationID: invID,
		ExitReason:   seat.ExitReason("vanished"),
	})
	if err == nil {
		t.Fatal("expected error for invalid exit_reason, got nil")
	}
}

func TestEndInvocation_UnknownInvocation(t *testing.T) {
	raw := openDB(t)
	err := seat.EndInvocation(context.Background(), raw, seat.EndInvocationRequest{
		InvocationID: "inv-nope",
		ExitReason:   seat.ExitOK,
	})
	if err == nil {
		t.Fatal("expected error for unknown invocation, got nil")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Minting rule: RingleaderSeatID must refer to a real, live ringleader seat
// for the requested PRD, and ParentSeatID must actually be that seat or one
// of its descendants (CodeRabbit review on PR #42).
// ─────────────────────────────────────────────────────────────────────────────

func TestMintSeat_RejectsFabricatedRingleaderSeatID(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	registerAgentCred(t, raw, "cred:w", seat.RoleWorker)

	_, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: "not-a-real-seat"}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: "not-a-real-seat", CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err == nil {
		t.Fatal("expected error minting under a fabricated ringleader seat id, got nil")
	}
}

func TestMintSeat_RejectsRingleaderFromWrongPRD(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	seedPRDAndTask(t, raw, "PRD-002", "")
	rlOther := mintRingleaderSeat(t, raw, "PRD-002")
	registerAgentCred(t, raw, "cred:w", seat.RoleWorker)

	_, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlOther}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: rlOther, CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err == nil {
		t.Fatal("expected error minting for PRD-001 under a PRD-002 ringleader, got nil")
	}
}

func TestMintSeat_RejectsClosedRingleader(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	rlID := mintRingleaderSeat(t, raw, "PRD-001")
	must(t, seat.Transition(context.Background(), raw, rlID, seat.StatusActive))
	must(t, seat.Transition(context.Background(), raw, rlID, seat.StatusClosed))
	registerAgentCred(t, raw, "cred:w", seat.RoleWorker)

	_, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: rlID, CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err == nil {
		t.Fatal("expected error minting under a closed ringleader seat, got nil")
	}
}

func TestMintSeat_RejectsParentNotDescendantOfMinter(t *testing.T) {
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	rl1 := mintRingleaderSeat(t, raw, "PRD-001")
	registerAgentCred(t, raw, "cred:w", seat.RoleWorker)

	// A worker seat under a different (fabricated) parent that rl1 did not mint.
	_, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rl1}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: "some-unrelated-seat", CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err == nil {
		t.Fatal("expected error minting with a parent unrelated to the minting ringleader, got nil")
	}
}

func TestMintSeat_AllowsGrandchildParentage(t *testing.T) {
	// Judge disputes mint a fresh judge seat (§5.4); the ringleader itself
	// remains the minter, but the new seat's parent can be any seat the
	// ringleader is the ancestor of, not only the ringleader directly.
	raw := openDB(t)
	seedPRDAndTask(t, raw, "PRD-001", "TASK-001")
	rlID := mintRingleaderSeat(t, raw, "PRD-001")
	registerAgentCred(t, raw, "cred:w", seat.RoleWorker)
	registerAgentCred(t, raw, "cred:j", seat.RoleJudge)

	workerID, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: rlID, CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint worker: %v", err)
	}

	_, err = seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleJudge, PRDID: "PRD-001", TaskID: "TASK-001",
		ParentSeatID: workerID, CredentialID: "cred:j", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("expected grandchild parentage (judge under worker) to be allowed: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Transition: concurrent status change is detected, not silently overwritten
// (CodeRabbit review on PR #42).
// ─────────────────────────────────────────────────────────────────────────────

func TestTransition_DetectsConcurrentChange(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusActive))

	// Simulate a second actor closing the seat between another caller's read
	// and write by closing it directly, then trying to apply a transition
	// that was decided against the pre-close status.
	must(t, seat.Transition(context.Background(), raw, id, seat.StatusClosed))

	// A stale caller that decided "active -> expired" before the close above
	// must not be able to silently stomp the closed status.
	err := seat.Transition(context.Background(), raw, id, seat.StatusExpired)
	if err == nil {
		t.Fatal("expected error applying a transition against an already-changed status, got nil")
	}
}

func TestRenewLease(t *testing.T) {
	ctx := context.Background()
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	invID, err := seat.StartInvocation(ctx, raw, seat.StartInvocationRequest{
		SeatID: id, TaskID: "TASK-001", Purpose: seat.PurposeImplement,
	})
	if err != nil {
		t.Fatalf("StartInvocation: %v", err)
	}

	want := time.Date(2026, 1, 1, 12, 30, 0, 0, time.UTC)
	if err := seat.RenewLease(ctx, raw, invID, want); err != nil {
		t.Fatalf("RenewLease: %v", err)
	}
	var got time.Time
	if err := raw.QueryRowContext(ctx, `SELECT lease_expires_at FROM invocations WHERE id = ?`, invID).Scan(&got); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("lease_expires_at = %v, want %v", got, want)
	}

	// A zero expiry (paused lease) stores NULL.
	if err := seat.RenewLease(ctx, raw, invID, time.Time{}); err != nil {
		t.Fatalf("RenewLease(zero): %v", err)
	}
	var frozen sql.NullTime
	if err := raw.QueryRowContext(ctx, `SELECT lease_expires_at FROM invocations WHERE id = ?`, invID).Scan(&frozen); err != nil {
		t.Fatalf("query: %v", err)
	}
	if frozen.Valid {
		t.Errorf("lease_expires_at = %v, want NULL", frozen.Time)
	}

	if err := seat.EndInvocation(ctx, raw, seat.EndInvocationRequest{InvocationID: invID, ExitReason: seat.ExitOK}); err != nil {
		t.Fatalf("EndInvocation: %v", err)
	}
	if err := seat.RenewLease(ctx, raw, invID, want.Add(time.Minute)); err == nil {
		t.Error("RenewLease on an ended invocation succeeded")
	}
}

func TestEndInvocation_RecordsBudgetStopAndHarnessFields(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	invID, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID: id, TaskID: "TASK-001", Purpose: seat.PurposeImplement,
	})
	if err != nil {
		t.Fatalf("StartInvocation: %v", err)
	}
	cost, status := 0.00096, 429
	if err := seat.EndInvocation(context.Background(), raw, seat.EndInvocationRequest{
		InvocationID:   invID,
		ExitReason:     seat.ExitBudgetExhausted,
		CostUSD:        &cost,
		TerminalReason: "budget_exhausted",
		APIErrorStatus: &status,
	}); err != nil {
		t.Fatalf("EndInvocation: %v", err)
	}
	var exitReason, terminal string
	var apiStatus sql.NullInt64
	if err := raw.QueryRowContext(context.Background(),
		`SELECT exit_reason, terminal_reason, api_error_status FROM invocations WHERE id = ?`, invID).
		Scan(&exitReason, &terminal, &apiStatus); err != nil {
		t.Fatalf("query: %v", err)
	}
	if exitReason != "budget_exhausted" || terminal != "budget_exhausted" || apiStatus.Int64 != 429 {
		t.Errorf("got exit_reason=%q terminal_reason=%q api_error_status=%v", exitReason, terminal, apiStatus)
	}
}

func TestEndInvocation_NoTerminalReasonStoresNull(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	invID, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID: id, TaskID: "TASK-001", Purpose: seat.PurposeImplement,
	})
	if err != nil {
		t.Fatalf("StartInvocation: %v", err)
	}
	if err := seat.EndInvocation(context.Background(), raw, seat.EndInvocationRequest{
		InvocationID: invID, ExitReason: seat.ExitCrash,
	}); err != nil {
		t.Fatalf("EndInvocation: %v", err)
	}
	var terminal sql.NullString
	var apiStatus sql.NullInt64
	if err := raw.QueryRowContext(context.Background(),
		`SELECT terminal_reason, api_error_status FROM invocations WHERE id = ?`, invID).
		Scan(&terminal, &apiStatus); err != nil {
		t.Fatalf("query: %v", err)
	}
	if terminal.Valid || apiStatus.Valid {
		t.Errorf("got terminal_reason=%v api_error_status=%v, want NULLs when no result arrived", terminal, apiStatus)
	}
}

func TestSetHarnessSession(t *testing.T) {
	raw := openDB(t)
	id := mintTestSeat(t, raw)
	ctx := context.Background()
	if err := seat.SetHarnessSession(ctx, raw, id, "577b6ab1"); err != nil {
		t.Fatalf("SetHarnessSession: %v", err)
	}
	// Same id again (every --resume reports it) is fine.
	if err := seat.SetHarnessSession(ctx, raw, id, "577b6ab1"); err != nil {
		t.Fatalf("SetHarnessSession again: %v", err)
	}
	got, err := seat.HarnessSession(ctx, raw, id)
	if err != nil || got != "577b6ab1" {
		t.Fatalf("HarnessSession = %q, %v", got, err)
	}
	// A different id means the resume silently forked; refuse to overwrite.
	if err := seat.SetHarnessSession(ctx, raw, id, "ffffffff"); err == nil {
		t.Error("SetHarnessSession overwrote a different session id")
	}
	if err := seat.SetHarnessSession(ctx, raw, "no-such-seat", "x"); err == nil {
		t.Error("SetHarnessSession on a missing seat succeeded")
	}
}
