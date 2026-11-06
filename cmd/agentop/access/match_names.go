package access

import (
	"fmt"
	"strings"
)

// evaluate relates one rule to one call. Tool-name matching lives here; a rule with a
// specifier is handed to the tool family that understands it, and a specifier no family
// handles is unevaluable, never silently a non-match.
func evaluate(r Rule, c Call, ctx MatchContext) evalResult {
	matched, caveats, note := toolNameMatches(r, c.Tool)
	res := evalResult{caveats: caveats}
	if note != "" {
		res.caveats = append(res.caveats, note)
	}
	if !matched {
		return res
	}

	_, pattern := matchKey(r.Tool, r.Pattern)
	// "*" alone matches every use. The docs spell it out for Write, Grep, Glob and NotebookEdit
	// ("a path other than *"), and Bash(*) is the bare tool; treat a lone * the same for every
	// tool rather than leave it to each family.
	if pattern == "" || pattern == "*" {
		res.state = evalMatch
		return res
	}
	return evaluateSpecifier(r, pattern, c, ctx, res)
}

// evaluateSpecifier handles rules with a parenthesised specifier. Each tool family adds a case
// here; until a family exists its rules are unevaluable.
func evaluateSpecifier(r Rule, pattern string, c Call, ctx MatchContext, res evalResult) evalResult {
	// Rules that Claude Code accepts but never matches against a path: Write, Grep, Glob,
	// NotebookEdit and MultiEdit(path) with a path other than *. Say so, so a user who believes
	// Write(docs/**) protects docs learns that it does not.
	if neverMatchesPath(r.Tool) && pattern != "*" {
		res.state = evalNoMatch
		res.caveats = append(res.caveats, fmt.Sprintf(
			"%s never matches: Claude Code checks file permissions against Edit(path) and Read(path) rules; write %s",
			r.Raw, equivalentPathRule(r.Tool, pattern)))
		return res
	}
	if strings.HasPrefix(r.Tool, "mcp__") {
		// Claude Code skips an mcp__ rule that has parentheses.
		res.state = evalNoMatch
		return res
	}
	if r.Tool == "Bash" {
		return evaluateBash(r, pattern, c, res)
	}
	if pathRuleFamily(r.Tool) {
		return evaluatePath(r, pattern, c, ctx, res)
	}
	res.state = evalUnknown
	return res
}

func neverMatchesPath(tool string) bool {
	switch tool {
	case "Write", "Grep", "Glob", "NotebookEdit", "MultiEdit":
		return true
	}
	return false
}

func equivalentPathRule(tool, pattern string) string {
	switch tool {
	case "Grep", "Glob":
		return "Read(" + pattern + ")"
	}
	return "Edit(" + pattern + ")"
}

// toolNameMatches reports whether rule r's TOOL NAME covers the call's tool, applying the
// docs' rules for globs, MCP servers and the Edit and Read equivalences.
func toolNameMatches(r Rule, tool string) (matched bool, caveats []string, note string) {
	name := r.Tool
	if name == "" {
		return false, nil, ""
	}

	// MCP rules: mcp__server, mcp__server__*, mcp__server__tool. A rule with parentheses is
	// skipped by Claude Code; that is handled by the caller, which sees the pattern.
	if strings.HasPrefix(name, "mcp__") || strings.HasPrefix(tool, "mcp__") && strings.ContainsAny(name, "*") {
		return mcpMatches(r, name, tool)
	}

	// Name globs. A deny or ask rule accepts a glob in the tool-name position; an allow rule
	// accepts one only after a literal mcp__<server>__ prefix, handled above, so any other allow
	// glob is skipped.
	if strings.Contains(name, "*") {
		if r.Decision == Allow {
			return false, nil, ""
		}
		return globMatch(name, tool), nil, ""
	}

	if name == tool {
		return true, nil, ""
	}
	switch {
	case name == "Edit" && isEditTool(tool):
		return true, nil, ""
	case name == "Read" && (tool == "Grep" || tool == "Glob") && r.Decision != Allow:
		// Read deny and ask rules are applied to Grep and Glob on a best-effort basis; an
		// allow is not.
		return true, nil, "Read rules are applied to Grep and Glob on a best-effort basis"
	case name == "Read" && (tool == "Edit" || tool == "Write") && r.Decision == Deny:
		// "A Read deny rule also blocks the Edit and Write tools on the same path."
		return true, nil, ""
	}
	return false, nil, ""
}

func isEditTool(tool string) bool {
	switch tool {
	case "Edit", "Write", "NotebookEdit", "MultiEdit":
		return true
	}
	return false
}

// mcpMatches applies the MCP naming rules. A server name may itself contain "__", which makes
// "mcp__a__b__c" ambiguous (server a, tool b__c; or server a__b, tool c). The docs say a deny or
// ask rule covers every reading, and an allow rule does not: so an allow on an ambiguous name is
// not evaluated.
func mcpMatches(r Rule, name, tool string) (bool, []string, string) {
	if !strings.HasPrefix(tool, "mcp__") {
		// A glob such as mcp__* (deny/ask) still must match a non-MCP name as a plain glob.
		if strings.Contains(name, "*") && r.Decision != Allow {
			return globMatch(name, tool), nil, ""
		}
		return false, nil, ""
	}
	if !strings.Contains(name, "*") {
		if name == tool {
			return true, nil, ""
		}
		// mcp__server: any tool of that server.
		rest := strings.TrimPrefix(tool, "mcp__")
		srvRule := strings.TrimPrefix(name, "mcp__")
		if srvRule == "" || strings.Contains(srvRule, "__") {
			return false, nil, ""
		}
		if !strings.HasPrefix(rest, srvRule+"__") {
			return false, nil, ""
		}
		if strings.Contains(strings.TrimPrefix(rest, srvRule+"__"), "__") && r.Decision == Allow {
			// The server could be "srv" or something longer: an allow does not cover the longer
			// reading, so we cannot say it matches.
			return false, nil, fmt.Sprintf("%s: the server name in %s is ambiguous (it may contain \"__\"); write mcp__<server>__* to allow it", r.Raw, tool)
		}
		return true, nil, ""
	}

	// A glob. Deny and ask accept any; allow only after a literal mcp__<server>__ prefix whose
	// server segment is glob-free and non-empty.
	if r.Decision == Allow {
		rest := strings.TrimPrefix(name, "mcp__")
		server, _, ok := strings.Cut(rest, "__")
		if !ok || server == "" || strings.Contains(server, "*") {
			return false, nil, ""
		}
	}
	return globMatch(name, tool), nil, ""
}

// globMatch matches s against a pattern in which * matches any run of characters (including
// none). The whole string must match. It is the classic two-pointer algorithm: linear in
// len(s) + len(pattern) for the work done per star, with no backtracking blow-up.
func globMatch(pattern, s string) bool {
	pattern = collapseStars(pattern)
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && pattern[p] == s[i]:
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
