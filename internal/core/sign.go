package core

import (
	"context"
	"fmt"

	"github.com/Masked-Kunsiquat/arbiter/internal/gitsign"
)

// SignFunc signs payload with the human's key, client-side, and returns the
// armored SSH signature (internal/humansig.Signer.Sign).
type SignFunc func(ctx context.Context, payload []byte) (string, error)

// LockPRD creates the signed PRD lock tag (or, with req.Amend, the next
// version): the core prepares the tag object, sign signs it in this
// process, and the core verifies and writes it (§8.C).
func (s *Session) LockPRD(ctx context.Context, req gitsign.LockRequest, sign SignFunc) (*gitsign.Completed, error) {
	return s.signRoundTrip(ctx, MethodSignPrepareLock, req, sign)
}

// MergeFinal creates the human-signed feature → main merge commit (§8.C,
// §8.D "Human capstone") the same way.
func (s *Session) MergeFinal(ctx context.Context, req gitsign.MergeRequest, sign SignFunc) (*gitsign.Completed, error) {
	return s.signRoundTrip(ctx, MethodSignPrepareMerge, req, sign)
}

func (s *Session) signRoundTrip(ctx context.Context, prepareMethod string, req any, sign SignFunc) (*gitsign.Completed, error) {
	var prep gitsign.Prepared
	if err := s.Call(ctx, prepareMethod, req, &prep); err != nil {
		return nil, err
	}
	sig, err := sign(ctx, prep.Payload)
	if err != nil {
		return nil, fmt.Errorf("signing %s: %w", prep.Ref, err)
	}
	var done gitsign.Completed
	if err := s.Call(ctx, MethodSignComplete, gitsign.CompleteRequest{RequestID: prep.RequestID, Signature: sig}, &done); err != nil {
		return nil, err
	}
	return &done, nil
}
