// Package gitsign is the core's side of human SSH signing (spec §8.C).
//
// The core never holds the human's key. For a PRD lock tag or the final
// feature → main merge, it builds the exact git object bytes to sign
// (Prepare*), hands them to the CLI, which signs them locally with the
// user's git signing setup (internal/humansig), and takes the signature
// back (Complete). Complete checks the signature against the repo's
// allowed_signers file (internal/allowedsigners), writes the signed object,
// and moves the ref. Because the core only ever sees bytes and signatures,
// this works the same whether the core runs on the laptop or a server (§10).
//
// The objects are byte-for-byte what `git tag -s` and `git commit -S` would
// write, so `git verify-tag`, `git verify-commit` and GitHub's Verified badge
// check them without Arbiter installed.
package gitsign

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// Namespace is the SSHSIG namespace git uses for commit and tag signatures.
const Namespace = "git"

// Ident is a git author, committer or tagger.
type Ident struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (i Ident) validate() error {
	if i.Name == "" || i.Email == "" {
		return errors.New("gitsign: identity needs a name and an email (git config user.name / user.email)")
	}
	if strings.ContainsAny(i.Name+i.Email, "<>\n\x00") {
		return fmt.Errorf("gitsign: identity %q <%s> contains '<', '>', a newline or NUL", i.Name, i.Email)
	}
	return nil
}

// format renders "Name <email> <unix-seconds> <+hhmm>" as git stores it.
func (i Ident) format(when time.Time) string {
	return fmt.Sprintf("%s <%s> %d %s", i.Name, i.Email, when.Unix(), when.Format("-0700"))
}

// message normalizes a commit or tag message the way git stores it: LF line
// endings and exactly one trailing newline.
func message(msg string) string {
	msg = strings.ReplaceAll(msg, "\r\n", "\n")
	return strings.TrimRight(msg, "\n") + "\n"
}

// TagPayload is the unsigned annotated tag object for tag pointing at object.
func TagPayload(object, objType, tag string, tagger Ident, when time.Time, msg string) []byte {
	return fmt.Appendf(nil, "object %s\ntype %s\ntag %s\ntagger %s\n\n%s",
		object, objType, tag, tagger.format(when), message(msg))
}

// CommitPayload is the unsigned commit object.
func CommitPayload(tree string, parents []string, author, committer Ident, when time.Time, msg string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "tree %s\n", tree)
	for _, p := range parents {
		fmt.Fprintf(&b, "parent %s\n", p)
	}
	fmt.Fprintf(&b, "author %s\ncommitter %s\n\n%s", author.format(when), committer.format(when), message(msg))
	return b.Bytes()
}

// AttachTagSig appends the armored signature to a tag payload, as git does:
// the signature follows the message, ending with a newline.
func AttachTagSig(payload []byte, sig string) []byte {
	out := bytes.Clone(payload)
	out = append(out, strings.TrimRight(sig, "\r\n")...)
	return append(out, '\n')
}

// AttachCommitSig adds the signature to a commit payload as a header
// ("gpgsig" in SHA-1 repos, "gpgsig-sha256" in SHA-256 ones) at the end of
// the header block, continuation lines indented by one space.
func AttachCommitSig(payload []byte, sig, header string) ([]byte, error) {
	end := bytes.Index(payload, []byte("\n\n"))
	if end < 0 {
		return nil, errors.New("gitsign: commit payload has no header/message separator")
	}
	var h bytes.Buffer
	for i, line := range strings.Split(strings.ReplaceAll(strings.TrimRight(sig, "\r\n"), "\r\n", "\n"), "\n") {
		if i == 0 {
			h.WriteString(header + " ")
		} else {
			h.WriteString(" ")
		}
		h.WriteString(line + "\n")
	}
	out := make([]byte, 0, len(payload)+h.Len())
	out = append(out, payload[:end+1]...)
	out = append(out, h.Bytes()...)
	return append(out, payload[end+1:]...), nil
}

// Verify checks that sig is a valid git-namespace SSH signature over
// payload, made by a key that signers authorizes for principal at time at
// (the object's own timestamp, which is what git checks against). The
// verifying key comes from signers; the key embedded in sig only selects
// which line to check (§8.D). The supervisor key is refused: it may sign
// task commits, never human approvals. It returns the parsed signature, whose
// Armor is what gets written into the object.
func Verify(signers *allowedsigners.File, principal string, payload []byte, sig string, at time.Time) (*ledger.Sig, error) {
	parsed, err := ledger.ParseSSHSig(sig)
	if err != nil {
		return nil, err
	}
	if parsed.Namespace != Namespace {
		return nil, fmt.Errorf("gitsign: signature namespace %q, want %q", parsed.Namespace, Namespace)
	}
	if signers.IsSupervisorKey(parsed.PublicKey) {
		return nil, errors.New("gitsign: signed by Arbiter's supervisor key; human approvals need the human's key")
	}
	if err := signers.Authorize(principal, Namespace, parsed.PublicKey, at); err != nil {
		return nil, fmt.Errorf("gitsign: %w", err)
	}
	if err := ledger.VerifySSHSig(parsed.PublicKey, Namespace, payload, sig); err != nil {
		return nil, fmt.Errorf("gitsign: %w", err)
	}
	return parsed, nil
}
