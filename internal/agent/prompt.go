package agent

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// closeParts match the pieces of a closing tag the way a model may read
// one: "<" or a lookalike, then any whitespace, separator or invisible
// format character (zero-width space, joiner, ...), then "/" or a lookalike.
const (
	closeLT    = `[<\x{FF1C}\x{FE64}]`
	closeGap   = `[\s\p{Z}\p{Cf}]*`
	closeSlash = `[/\x{FF0F}\x{2215}\x{2044}]`
)

// tagPattern limits block tags to names that can't break the delimiter
// syntax themselves.
var tagPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Prompt is the stdin text for one invocation (§9.A "Prompt layout"): the
// role instruction first, then the untrusted material in delimited blocks.
// An instruction placed after a large blob reads like prompt injection, so
// the layout is fixed here rather than left to each caller.
type Prompt struct {
	Instruction string
	Blocks      []Block
}

// Block is one fenced piece of data: <Tag>\nBody\n</Tag>.
type Block struct {
	Tag  string
	Body string
}

// Render returns the prompt text. Inside each body, the block's own closing
// tag is escaped by putting a backslash before the slash (<\/tag). It is
// matched case-insensitively and loosely (closeParts: "< /diff", "</ diff",
// fullwidth and zero-width variants), since a model reads those as a close
// too, so data can't end its block early and pass what follows off as
// instructions.
func (p Prompt) Render() (string, error) {
	if strings.TrimSpace(p.Instruction) == "" {
		return "", errors.New("agent: prompt needs an instruction")
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(p.Instruction, "\n"))
	b.WriteString("\n")
	for _, blk := range p.Blocks {
		if !tagPattern.MatchString(blk.Tag) {
			return "", fmt.Errorf("agent: invalid prompt block tag %q", blk.Tag)
		}
		closing := regexp.MustCompile(`(?i)(` + closeLT + closeGap + `)(` + closeSlash + `)(` + closeGap + blk.Tag + `)`)
		body := closing.ReplaceAllString(blk.Body, `$1\$2$3`)
		fmt.Fprintf(&b, "\n<%s>\n%s", blk.Tag, body)
		if !strings.HasSuffix(body, "\n") {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "</%s>\n", blk.Tag)
	}
	return b.String(), nil
}
