package access

import (
	"fmt"
	"strings"
)

// bashCommand returns the command text of a Bash call, or false when the call carries none.
func bashCommand(c Call) (string, bool) {
	s, ok := c.Input["command"].(string)
	return s, ok
}

// bashWildcard compiles a Bash rule specifier into the form globMatch understands, applying
// the docs' rules (permissions, "Wildcard patterns"):
//
//   - "*" matches any text, including spaces, anywhere;
//   - a pattern with no "*" matches one exact command;
//   - a trailing " *" (a space, then a star) that is the pattern's only wildcard also matches
//     the bare command: Bash(ls *) matches "ls", but Bash(ls*) also matches "lsof";
//   - ":*" at the very end is an equivalent spelling of a trailing " *" (rewritten by matchKey
//     before a pattern gets here). Anywhere else the colon is a literal character.
//
// It returns the pattern to match and whether the "bare command" form applies.
func bashWildcard(pattern string) (pat string, bareOK bool) {
	// ":*" has already been rewritten to " *" by matchKey, which every caller goes through, so
	// it is not handled here: a second copy of that rule would be a second place to get it wrong.
	if strings.HasSuffix(pattern, " *") && strings.Count(pattern, "*") == 1 {
		return pattern, true
	}
	return pattern, false
}

// bashPatternMatches reports whether one subcommand matches a Bash specifier.
func bashPatternMatches(pattern, sub string) bool {
	pat, bareOK := bashWildcard(pattern)
	if globMatch(pat, sub) {
		return true
	}
	return bareOK && sub == strings.TrimSuffix(pat, " *")
}

// evaluateBash evaluates one rule against a Bash call.
//
// The semantics, from the docs ("Compound commands", "Wrappers"):
//
//   - deny and ask match when ANY subcommand matches, including one nested in a substitution,
//     a subshell or a loop body, and they see past wrappers and past any leading environment
//     assignment;
//   - allow covers a subcommand when it matches, and the CALL is allowed only when every
//     subcommand is covered. An allow rule does not see past an assignment of a variable it
//     cannot vouch for (the docs name "certain known-safe" variables and do not list them, so
//     none is assumed safe);
//   - a command that cannot be split is unparseable: a deny or ask rule cannot be said NOT to
//     match it, so it is unevaluable, and an allow rule approves nothing.
func evaluateBash(r Rule, pattern string, c Call, res evalResult) evalResult {
	cmd, ok := bashCommand(c)
	if !ok {
		// No command to examine. A deny or ask rule cannot be said not to apply; an allow
		// approves nothing.
		if r.Decision == Allow {
			return res
		}
		res.state = evalUnknown
		res.caveats = append(res.caveats, "this Bash call carries no command text to match")
		return res
	}

	p := splitCommand(cmd)
	if !p.ok {
		res.caveats = append(res.caveats, "the command cannot be analysed ("+p.reason+"), so Claude Code does not match rules against its parts")
		if r.Decision != Allow {
			res.state = evalUnknown
		}
		return res
	}

	for _, sub := range p.subs {
		stripped, assigned := stripWrappersNamed(sub)
		if bashPatternMatches(pattern, stripped) || (stripped != sub && bashPatternMatches(pattern, sub)) {
			if r.Decision == Allow && !onlySafeAssignments(assigned) {
				res.caveats = append(res.caveats, fmt.Sprintf(
					"%q starts with an environment variable assignment (%s); an allow rule matches past only known-safe variables, which Claude Code does not list (only NODE_ENV is shown in its examples)",
					abbreviate(sub), strings.Join(assigned, ", ")))
				continue
			}
			if r.Decision != Allow {
				res.state = evalMatch
				return res
			}
		}
	}
	return res
}

// bashAllowCoverage reports, for an allow-rule set, which subcommands of the command are
// covered by at least one matching allow rule. Used by Match to tell allow from partial.
func bashAllowCoverage(rules []Rule, c Call) (covered, total int, uncovered []string, ok bool) {
	cmd, has := bashCommand(c)
	if !has {
		return 0, 0, nil, false
	}
	p := splitCommand(cmd)
	if !p.ok || len(p.subs) == 0 {
		return 0, 0, nil, false
	}
	for _, sub := range p.subs {
		stripped, assigned := stripWrappersNamed(sub)
		hit := false
		for _, r := range rules {
			if r.Tool != "Bash" || r.Decision != Allow || r.Ignored != "" {
				continue
			}
			_, pat := matchKey(r.Tool, r.Pattern)
			if pat == "" || pat == "*" {
				hit = true
				break
			}
			if !onlySafeAssignments(assigned) {
				continue // see evaluateBash
			}
			if bashPatternMatches(pat, stripped) || (stripped != sub && bashPatternMatches(pat, sub)) {
				hit = true
				break
			}
		}
		if hit {
			covered++
		} else {
			uncovered = append(uncovered, sub)
		}
	}
	return covered, len(p.subs), uncovered, true
}

// bashBoundaryCaveat says when a deny or ask rule for a program did not match a command that
// nevertheless mentions that program by another route: "a deny or ask rule covers the
// invocation Claude usually produces and isn't a security boundary around the program."
//
// Kept narrow on purpose: it fires only for the three routes the docs name (a path to the
// program, sh/bash -c, an option placed before the subcommand), and only on a whole-word
// match, so "format" does not mention "rm".
func bashBoundaryCaveat(rules []Rule, c Call) string {
	cmd, ok := bashCommand(c)
	if !ok {
		return ""
	}
	for _, r := range rules {
		if r.Tool != "Bash" || r.Decision == Allow || r.Ignored != "" {
			continue
		}
		_, pat := matchKey(r.Tool, r.Pattern)
		prog, _, _ := strings.Cut(strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(pat, ":*"), " *")), " ")
		if prog == "" || strings.ContainsAny(prog, "*?") {
			continue
		}
		if mentionsProgram(cmd, prog) {
			return fmt.Sprintf("%s did not match, but the command still mentions %q by a route the rule does not cover (a path, sh -c, or options before the subcommand): a Bash rule is not a security boundary around the program", r.Raw, prog)
		}
	}
	return ""
}

// mentionsProgram reports whether prog appears in cmd as a whole word: delimited by the start
// or end of the text, whitespace, a quote, a slash or a shell metacharacter.
func mentionsProgram(cmd, prog string) bool {
	for from := 0; ; {
		k := strings.Index(cmd[from:], prog)
		if k < 0 {
			return false
		}
		start, end := from+k, from+k+len(prog)
		if wordBoundary(cmd, start-1) && wordBoundary(cmd, end) {
			return true
		}
		from = start + 1
	}
}

func wordBoundary(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return true
	}
	switch s[i] {
	case ' ', '\t', '\n', '\'', '"', '/', ';', '&', '|', '(', ')', '`', '$', '<', '>', '=':
		return true
	}
	return false
}

func abbreviate(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

// bashRuleCoversSome reports whether an allow rule covers at least one subcommand of the call,
// so the rules reported as deciding are the ones that did.
func bashRuleCoversSome(r Rule, c Call) bool {
	cmd, ok := bashCommand(c)
	if !ok {
		return false
	}
	_, pat := matchKey(r.Tool, r.Pattern)
	if pat == "" || pat == "*" {
		return true
	}
	p := splitCommand(cmd)
	if !p.ok {
		return false
	}
	for _, sub := range p.subs {
		stripped, assigned := stripWrappersNamed(sub)
		if !onlySafeAssignments(assigned) {
			continue
		}
		if bashPatternMatches(pat, stripped) || (stripped != sub && bashPatternMatches(pat, sub)) {
			return true
		}
	}
	return false
}
