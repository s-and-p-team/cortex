package access

import (
	"fmt"
	"path"
	"strings"
)

// File-path rules: Read(...) and Edit(...), which Claude Code applies to the built-in file tools
// and, best effort, to Grep and Glob. The rules are from the permissions docs ("Read and Edit",
// "How path patterns match"); this file implements the subset it can state exactly and reports
// everything else as unevaluable.
//
// Supported: * within a segment, ? one character, ** across directories, the four anchors
// (// absolute, ~/ home, / the settings source, and cwd-relative), gitignore's "a bare filename
// matches at any depth", and the allow-versus-deny/ask difference for single-segment directory
// patterns.
//
// Unsupported, so reported as unevaluable rather than guessed: ! negation, [...] character
// classes, and backslash escapes. Symlinks are not resolved, which every path match says.

const (
	// maxPathGlobCells bounds the pattern-by-path table pathGlob fills. Measured: the cost is
	// linear in the table (9 million cells take 17 ms plain and 1.3 s under -race -cover, the
	// slowest build the suite runs in), and the deepest real file path in 476 recorded tool calls
	// was 15 segments. 65,536 cells is a 250 x 250 table: far beyond any real rule and path, and
	// cheap everywhere. Past it the rule is reported unevaluable, never silently a non-match.
	maxPathGlobCells = 1 << 16
	symlinkCaveat    = "symlinks are not resolved: Claude Code also checks the file a symlink points to, which this view cannot see"
)

// callPath returns the path a file-tool call operates on, and whether there is one.
func callPath(c Call) (string, bool) {
	for _, k := range [...]string{"file_path", "notebook_path", "path"} {
		if v, ok := c.Input[k].(string); ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// pathRuleFamily reports whether a rule on tool applies to file paths. Only Read and Edit
// carry path specifiers; Write, Grep, Glob and NotebookEdit path rules never match (handled by
// the caller) and everything else is not a path rule.
func pathRuleFamily(tool string) bool { return tool == "Read" || tool == "Edit" }

// anchorFor resolves a pattern to an absolute base directory and the remaining pattern, by the
// rules in the docs' anchor table. ok is false when the anchor cannot be located because the
// information it needs (the cwd, the home or the config directory) is unknown.
func anchorFor(r Rule, pattern string, ctx MatchContext) (base, rest string, ok bool, why string) {
	switch {
	case strings.HasPrefix(pattern, "//"):
		return "/", strings.TrimPrefix(pattern, "//"), true, ""
	case strings.HasPrefix(pattern, "~/"):
		if ctx.Home == "" {
			return "", "", false, "the home directory is unknown"
		}
		return ctx.Home, strings.TrimPrefix(pattern, "~/"), true, ""
	case strings.HasPrefix(pattern, "/"):
		// "/path" anchors at the directory associated with the settings source that defines it.
		rest = strings.TrimPrefix(pattern, "/")
		switch r.Source {
		case User:
			dir := ctx.ConfigDir
			if dir == "" && ctx.Home != "" {
				dir = path.Join(ctx.Home, ".claude")
			}
			if dir == "" {
				return "", "", false, "the config directory is unknown"
			}
			return dir, rest, true, ""
		default:
			// project, local, managed, and CLI/session rules anchor at the primary working
			// directory. (A --settings FILE anchors at that file's directory, which is not
			// recorded; it is modelled as the cwd and flagged by the caller's layer note.)
			if ctx.Cwd == "" {
				return "", "", false, "the working directory is unknown"
			}
			return ctx.Cwd, rest, true, ""
		}
	default:
		rest = strings.TrimPrefix(pattern, "./")
		if ctx.Cwd == "" {
			return "", "", false, "the working directory is unknown"
		}
		return ctx.Cwd, rest, true, ""
	}
}

// evaluatePath evaluates a Read or Edit rule against a call that names a file.
func evaluatePath(r Rule, pattern string, c Call, ctx MatchContext, res evalResult) evalResult {
	unevaluable := func(why string) evalResult {
		res.caveats = append(res.caveats, fmt.Sprintf("%s: %s", r.Raw, why))
		// An allow rule that cannot be evaluated approves nothing; a deny or ask rule that
		// cannot be evaluated might be the one that applies.
		res.state = evalUnknown
		return res
	}

	if why := unsupportedPathSyntax(pattern); why != "" {
		return unevaluable(why)
	}
	target, ok := callPath(c)
	if !ok {
		if r.Decision == Allow {
			return res
		}
		return unevaluable("this call names no file path to match")
	}

	base, rest, ok, why := anchorFor(r, pattern, ctx)
	if !ok {
		return unevaluable(why)
	}

	// Resolve the call's path: relative to the cwd, cleaned.
	if !path.IsAbs(target) {
		if ctx.Cwd == "" {
			return unevaluable("the call's path is relative and the working directory is unknown")
		}
		target = path.Join(ctx.Cwd, target)
	}
	target = path.Clean(target)
	base = path.Clean(base)

	// A rule only matches files under its anchor.
	rel, under := relUnder(base, target)
	if !under {
		res.caveats = append(res.caveats, symlinkCaveat)
		return res
	}

	res.caveats = append(res.caveats, symlinkCaveat)
	matched, evaluated := pathPatternMatchesBounded(r.Decision, pattern, rest, rel)
	if !evaluated {
		return unevaluable("the pattern and the path are too large to evaluate")
	}
	if matched {
		res.state = evalMatch
	}
	return res
}

// relUnder returns target relative to base, and whether target is base or beneath it.
func relUnder(base, target string) (string, bool) {
	if base == "/" {
		return strings.TrimPrefix(target, "/"), true
	}
	if target == base {
		return "", true
	}
	if strings.HasPrefix(target, base+"/") {
		return strings.TrimPrefix(target, base+"/"), true
	}
	return "", false
}

// pathPatternMatchesBounded matches rel (a path relative to the anchor) against rest (the pattern with
// its anchor prefix removed), applying gitignore's depth rules.
//
// A pattern with no slash in it (".env", "*.env") is a bare name: gitignore matches it at any
// depth under the anchor. A pattern with a slash is matched from the anchor. The one exception
// the docs spell out is a single-segment DIRECTORY pattern written without an anchor ("src/**"):
// a deny or ask rule matches it at any depth, an allow rule only at the anchor.
func pathPatternMatchesBounded(d Decision, original, rest, rel string) (matched, evaluated bool) {
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return rel == "", true
	}
	anchored := strings.HasPrefix(original, "//") || strings.HasPrefix(original, "~/") ||
		strings.HasPrefix(original, "/") || strings.HasPrefix(original, "./")
	if anchored {
		return pathGlobBounded(rest, rel)
	}

	dirPattern := strings.HasSuffix(rest, "/**")
	head := strings.TrimSuffix(rest, "/**")
	singleSegment := !strings.Contains(head, "/")

	switch {
	case !strings.Contains(rest, "/"):
		// A bare name: any depth, for every rule type.
		return pathGlobBounded("**/"+rest, rel)
	case dirPattern && singleSegment && d == Allow:
		return pathGlobBounded(rest, rel)
	case dirPattern && singleSegment:
		return pathGlobBounded("**/"+rest, rel)
	default:
		// A multi-segment pattern ("src/components/**", "docs/*.md") matches from the anchor.
		return pathGlobBounded(rest, rel)
	}
}

// unsupportedPathSyntax reports pattern syntax this matcher does not implement.
func unsupportedPathSyntax(pattern string) string {
	switch {
	case strings.HasPrefix(pattern, "!"):
		return "a ! negation carves paths out of earlier rules from the same file, which this view does not model"
	case strings.ContainsAny(pattern, "["):
		return "a [...] character class is not supported"
	case strings.Contains(pattern, `\`):
		return "a backslash escape is not supported"
	}
	return ""
}

// pathGlob matches a slash-separated path against a gitignore-style pattern: * and ? within a
// segment, ** across segments. A trailing /** also matches the named root, as in the docs.
//
// It fills a table of (pattern segment, path segment) bottom-up rather than recursing. The cost
// is len(pattern segments) x len(path segments) however many ** it contains, and it uses a
// constant amount of stack: a recursive version needed one frame per path segment, and a 3,000
// segment path made the goroutine stack grow to a size the race detector spent seconds
// clearing.
func pathGlob(pattern, p string) bool {
	ok, _ := pathGlobBounded(pattern, p)
	return ok
}

// pathGlobBounded is pathGlob, also reporting false for "evaluated" when the pattern and path
// are too large to evaluate within the bound, so a caller can say so instead of reporting a
// non-match it did not establish.
func pathGlobBounded(pattern, p string) (matched, evaluated bool) {
	if pattern == "" {
		return p == "", true
	}
	ps := splitSegments(pattern)
	xs := splitSegments(p)
	n, m := len(ps), len(xs)
	if n*m > maxPathGlobCells {
		return false, false
	}

	// match[i][j]: pattern segments i.. match path segments j... Two rows suffice: row i depends
	// on row i+1 and on row i itself (for **).
	next := make([]bool, m+1) // row i+1
	cur := make([]bool, m+1)  // row i
	next[m] = true            // all pattern consumed, all path consumed
	for i := n - 1; i >= 0; i-- {
		for j := m; j >= 0; j-- {
			switch {
			case ps[i] == "**":
				// zero segments: skip the ** (row i+1, same j); one more: stay on the ** (row i, j+1)
				cur[j] = next[j] || (j < m && cur[j+1])
			case j == m:
				cur[j] = false
			default:
				cur[j] = next[j+1] && segGlob(ps[i], xs[j])
			}
		}
		next, cur = cur, next
		for k := range cur {
			cur[k] = false
		}
	}
	return next[0], true
}

func splitSegments(s string) []string {
	s = strings.Trim(s, "/")
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

// segGlob matches one path segment against a pattern with * (any run, no slash) and ?.
func segGlob(pattern, s string) bool {
	// Consecutive stars match exactly what one star does. Collapsing them keeps a hostile
	// pattern of ten thousand of them from costing ten thousand steps per path segment.
	pattern = collapseStars(pattern)
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// collapseStars replaces each run of "*" with a single "*".
func collapseStars(p string) string {
	if !strings.Contains(p, "**") {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); i++ {
		if p[i] == '*' && i > 0 && p[i-1] == '*' {
			continue
		}
		b.WriteByte(p[i])
	}
	return b.String()
}
