package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/core"
	"github.com/Masked-Kunsiquat/arbiter/internal/gitsign"
	"github.com/Masked-Kunsiquat/arbiter/internal/humansig"
	"github.com/Masked-Kunsiquat/arbiter/internal/prd"
)

const prdUsage = `usage: arbiter prd init "<title>" [--branch <name>]
       arbiter prd lock <prd-id>
       arbiter prd amend <prd-id>
       arbiter prd review <prd-id> [--into <branch>]`

// prdArgs is a parsed `arbiter prd` command line.
type prdArgs struct {
	Sub    string // init, lock, amend or review
	Title  string // init
	Branch string // init: "" means feature/<lowercased id>
	ID     string // lock, amend, review
	Into   string // review: the branch to merge into
}

// parsePRDArgs accepts flags before or after the positional argument, as
// "--flag value" or "--flag=value". Anything left over is an error.
func parsePRDArgs(args []string) (prdArgs, error) {
	if len(args) == 0 {
		return prdArgs{}, errors.New(prdUsage)
	}
	a := prdArgs{Sub: args[0]}
	var flagName string
	switch a.Sub {
	case "init":
		flagName = "--branch"
	case "review":
		flagName = "--into"
		a.Into = "main"
	case "lock", "amend":
	default:
		return prdArgs{}, fmt.Errorf("unknown prd command %q\n%s", a.Sub, prdUsage)
	}

	var positional []string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		name, val, hasVal := strings.Cut(arg, "=")
		switch {
		case flagName != "" && name == flagName:
			if !hasVal {
				if i+1 >= len(rest) {
					return prdArgs{}, fmt.Errorf("%s needs a value", flagName)
				}
				i++
				val = rest[i]
			}
			if val == "" {
				return prdArgs{}, fmt.Errorf("%s needs a value", flagName)
			}
			if a.Sub == "init" {
				a.Branch = val
			} else {
				a.Into = val
			}
		case strings.HasPrefix(arg, "-"):
			return prdArgs{}, fmt.Errorf("unknown flag %q", arg)
		default:
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 {
		return prdArgs{}, fmt.Errorf("%s needs exactly one argument\n%s", a.Sub, prdUsage)
	}
	if a.Sub == "init" {
		if strings.TrimSpace(positional[0]) == "" {
			return prdArgs{}, errors.New("the title must not be empty")
		}
		a.Title = positional[0]
		return a, nil
	}
	if !prd.IDRe.MatchString(positional[0]) {
		return prdArgs{}, fmt.Errorf("bad PRD id %q (want PRD-<digits>, at least three)", positional[0])
	}
	a.ID = positional[0]
	return a, nil
}

// runPRD implements `arbiter prd init|lock|amend|review` (spec §2, §9.B).
func runPRD(ctx context.Context, args []string) error {
	a, err := parsePRDArgs(args)
	if err != nil {
		return err
	}
	root, err := repoRoot()
	if err != nil {
		return err
	}
	switch a.Sub {
	case "init":
		return prdInit(ctx, root, a)
	case "lock", "amend":
		return prdLock(ctx, root, a)
	default:
		return prdReview(ctx, root, a)
	}
}

// repoRoot is the parent of the .arbiter directory found by walking up.
func repoRoot() (string, error) {
	dbPath, err := findStateDB()
	if err != nil {
		return "", err
	}
	return filepath.Dir(filepath.Dir(dbPath)), nil
}

var prdFileRe = regexp.MustCompile(`^PRD-(\d+)\.md$`)

// nextPRDID returns the id after the highest PRD-<n>.md among names.
func nextPRDID(names []string) string {
	highest := 0
	for _, name := range names {
		if m := prdFileRe.FindStringSubmatch(name); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				highest = max(highest, n)
			}
		}
	}
	return fmt.Sprintf("PRD-%03d", highest+1)
}

// prdRelPath is the PRD file's repo-relative path.
func prdRelPath(id string) string { return ".arbiter/prds/" + id + ".md" }

// formatLineErrors renders a parse error as one "<path>:<line>: <msg>" per
// problem ("<path>: <msg>" when it has no line), sorted by line with the
// unlined ones last. Other errors become a single "<path>: <err>".
func formatLineErrors(path string, err error) []string {
	var pe *prd.ParseError
	if !errors.As(err, &pe) {
		return []string{path + ": " + err.Error()}
	}
	errs := append([]prd.LineError(nil), pe.Errs...)
	sort.SliceStable(errs, func(i, j int) bool {
		a, b := errs[i].Line, errs[j].Line
		if a == 0 || b == 0 {
			return b == 0 && a != 0
		}
		return a < b
	})
	out := make([]string, len(errs))
	for i, le := range errs {
		if le.Line == 0 {
			out[i] = path + ": " + le.Msg
		} else {
			out[i] = path + ":" + strconv.Itoa(le.Line) + ": " + le.Msg
		}
	}
	return out
}

// git runs git in dir and returns its trimmed stdout.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(stdout.String()), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func prdInit(ctx context.Context, root string, a prdArgs) error {
	dir := filepath.Join(root, ".arbiter", "prds")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("arbiter prd init: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("arbiter prd init: %w", err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	id := nextPRDID(names)
	branch := a.Branch
	if branch == "" {
		branch = "feature/" + strings.ToLower(id)
	}
	createdBy := ""
	if cfg, err := humansig.LoadConfig(ctx, root); err == nil && cfg.Name != "" {
		createdBy = "human:" + cfg.Name
	}

	path := filepath.Join(dir, id+".md")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("arbiter prd init: %w", err)
	}
	if _, err := f.Write(prd.Template(id, a.Title, branch, createdBy)); err != nil {
		_ = f.Close()
		return fmt.Errorf("arbiter prd init: writing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("arbiter prd init: writing %s: %w", path, err)
	}
	fmt.Printf("created %s\n", path)
	fmt.Printf("Fill in its sections, then run 'arbiter prd lock %s' to lock it.\n", id)
	return nil
}

// loadPRD reads and parses a PRD file, printing every problem to errOut
// before failing. The id in its frontmatter must match.
func loadPRD(root, id string, errOut io.Writer, verb string) (path string, src []byte, p *prd.PRD, err error) {
	rel := prdRelPath(id)
	path = filepath.Join(root, filepath.FromSlash(rel))
	src, err = os.ReadFile(path)
	if err != nil {
		return "", nil, nil, fmt.Errorf("arbiter prd %s: %w", verb, err)
	}
	p, err = prd.Parse(src)
	if err != nil {
		lines := formatLineErrors(rel, err)
		for _, l := range lines {
			fmt.Fprintln(errOut, l)
		}
		return "", nil, nil, fmt.Errorf("arbiter prd %s: %s does not parse (%d problem(s))", verb, rel, len(lines))
	}
	if p.ID != id {
		return "", nil, nil, fmt.Errorf("arbiter prd %s: %s has id %s in its frontmatter, not %s", verb, rel, p.ID, id)
	}
	return path, src, p, nil
}

// humanSigner resolves the human's identity and signing key from git config
// (§8.C); the private key never leaves their signing setup.
func humanSigner(ctx context.Context, root string) (gitsign.Signer, core.SignFunc, error) {
	cfg, err := humansig.LoadConfig(ctx, root)
	if err != nil {
		return gitsign.Signer{}, nil, err
	}
	hs, err := humansig.NewSigner(cfg)
	if err != nil {
		return gitsign.Signer{}, nil, err
	}
	pub, err := hs.PublicKey(ctx)
	if err != nil {
		return gitsign.Signer{}, nil, err
	}
	return gitsign.Signer{
		Ident:     gitsign.Ident{Name: cfg.Name, Email: cfg.Email},
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
	}, hs.Sign, nil
}

// prdLock implements `prd lock` and `prd amend` (§2.A): record status,
// spec_hash and created_by in the file, commit only that file, then have the
// core prepare the tag for the human's key to sign.
func prdLock(ctx context.Context, root string, a prdArgs) error {
	verb, subject := "lock", "Lock"
	if a.Sub == "amend" {
		verb, subject = "amend", "Amend"
	}
	path, src, p, err := loadPRD(root, a.ID, os.Stderr, verb)
	if err != nil {
		return err
	}
	rel := prdRelPath(a.ID)

	hash, err := prd.SpecHash(src)
	if err != nil {
		return fmt.Errorf("arbiter prd %s: %w", verb, err)
	}
	createdBy := p.CreatedBy
	if createdBy == "" {
		if cfg, err := humansig.LoadConfig(ctx, root); err == nil && cfg.Name != "" {
			createdBy = "human:" + cfg.Name
		}
	}
	out, err := prd.SetArbiterFields(src, prd.ArbiterFields{Status: prd.StatusLocked, SpecHash: hash, CreatedBy: createdBy})
	if err != nil {
		return fmt.Errorf("arbiter prd %s: %w", verb, err)
	}
	if !bytes.Equal(out, src) {
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return fmt.Errorf("arbiter prd %s: %w", verb, err)
		}
	}

	if _, err := git(ctx, root, "add", "--", rel); err != nil {
		return fmt.Errorf("arbiter prd %s: %w", verb, err)
	}
	if _, err := git(ctx, root, "diff", "--cached", "--quiet", "--", rel); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			return fmt.Errorf("arbiter prd %s: %w", verb, err)
		}
		// Only the PRD file: anything else the human has staged stays staged.
		if _, err := git(ctx, root, "commit", "-m", subject+" "+a.ID, "--", rel); err != nil {
			return fmt.Errorf("arbiter prd %s: %w", verb, err)
		}
	}

	signer, sign, err := humanSigner(ctx, root)
	if err != nil {
		return fmt.Errorf("arbiter prd %s: %w", verb, err)
	}
	sess, err := connectCore(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()
	done, err := sess.LockPRD(ctx, gitsign.LockRequest{PRDID: a.ID, Amend: a.Sub == "amend", Signer: signer}, sign)
	if err != nil {
		return fmt.Errorf("arbiter prd %s: %w", verb, err)
	}
	fmt.Printf("%s: signed %s (object %s)\n", a.ID, strings.TrimPrefix(done.Ref, "refs/tags/"), done.ObjectSHA)
	return nil
}

// prdReview implements `prd review` (§2.A, §8.C): summarize the PRD and,
// once every task is done, offer the signed final merge.
func prdReview(ctx context.Context, root string, a prdArgs) error {
	_, _, p, err := loadPRD(root, a.ID, os.Stderr, "review")
	if err != nil {
		return err
	}
	sess, err := connectCore(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()
	st, err := sess.GetPRD(ctx, a.ID)
	if err != nil {
		return fmt.Errorf("arbiter prd review: %w", err)
	}
	status := st.Status
	if status == "" {
		status = prd.StatusDraft
	}
	fmt.Printf("%s: %s\n", p.ID, p.Title)
	fmt.Printf("  target branch: %s\n", p.TargetBranch)
	fmt.Printf("  status:        %s\n", status)
	fmt.Printf("  invariants: %d, boundaries: %d, acceptance criteria: %d\n", len(p.Invariants), len(p.Boundaries), len(p.Criteria))
	for _, b := range p.Boundaries {
		fmt.Printf("  boundary: %s\n", b.Pattern)
	}

	if status != prd.StatusCompleted {
		fmt.Println("The final signed merge is offered once every task is done.")
		return nil
	}
	// TODO(#12): run the integration pass before offering the merge (§5.6).
	signer, sign, err := humanSigner(ctx, root)
	if err != nil {
		return fmt.Errorf("arbiter prd review: %w", err)
	}
	done, err := sess.MergeFinal(ctx, gitsign.MergeRequest{PRDID: a.ID, Source: p.TargetBranch, Target: a.Into, Signer: signer}, sign)
	if err != nil {
		return fmt.Errorf("arbiter prd review: %w", err)
	}
	fmt.Printf("%s: merged %s into %s (commit %s)\n", a.ID, p.TargetBranch, a.Into, done.ObjectSHA)
	return nil
}
