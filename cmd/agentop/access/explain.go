package access

import (
	"fmt"
	"net/url"
	"strings"
)

// maxExplainLen bounds what a user may ask to explain. The longest real Bash command in the
// transcripts is far below it, and a Bash command over 10,000 characters is not analysed anyway.
const maxExplainLen = 12000

// ParseExplain turns what a user types, "Tool(content)" or just "Tool", into the Call it
// describes. The content is the tool's primary argument: a Bash command, a file path, a URL, a
// subagent type, a skill name. For WebFetch, "domain:host" is accepted as shorthand for a fetch
// of https://host/.
//
// It is the inverse of how a rule is written, deliberately: a user who knows the rule syntax
// can ask about a call in the same syntax.
func ParseExplain(s string) (Call, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Call{}, fmt.Errorf("nothing to explain")
	}
	if len(s) > maxExplainLen {
		return Call{}, fmt.Errorf("too long to explain (%d characters; the limit is %d)", len(s), maxExplainLen)
	}

	tool, content := s, ""
	hasContent := false
	if i := strings.IndexByte(s, '('); i >= 0 {
		if !strings.HasSuffix(s, ")") {
			return Call{}, fmt.Errorf("%q has an opening parenthesis and no closing one at the end", Clean(abbreviate(s)))
		}
		tool, content, hasContent = s[:i], s[i+1:len(s)-1], true
	}
	if !validToolName(tool) {
		return Call{}, fmt.Errorf("%q is not a tool name (letters, digits, _ and - only)", Clean(abbreviate(tool)))
	}

	c := Call{Tool: tool, Input: map[string]any{}}
	if !hasContent {
		return c, nil
	}
	switch {
	case tool == "Bash" || tool == "PowerShell":
		c.Input["command"] = content
	case tool == "Read" || tool == "Edit" || tool == "Write" || tool == "MultiEdit":
		c.Input["file_path"] = content
	case tool == "NotebookEdit":
		c.Input["notebook_path"] = content
	case tool == "Grep" || tool == "Glob":
		c.Input["path"] = content
	case tool == "WebFetch":
		if host, ok := strings.CutPrefix(content, "domain:"); ok {
			c.Input["url"] = "https://" + strings.TrimSpace(host) + "/"
		} else if u, err := url.Parse(content); err == nil && u.Host != "" {
			c.Input["url"] = content
		} else {
			return Call{}, fmt.Errorf("WebFetch(...) takes a URL or domain:host, not %q", Clean(abbreviate(content)))
		}
	case tool == "Agent":
		c.Input["subagent_type"] = content
	case tool == "Skill":
		c.Input["skill"] = content
	default:
		// An MCP tool, or one this view has no primary field for: there is no argument to carry.
		return Call{}, fmt.Errorf("don't know which argument %s(...) names; write the tool alone, or one of Bash, Read, Edit, WebFetch, Agent, Skill", Clean(tool))
	}
	return c, nil
}

func validToolName(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for _, r := range s {
		switch {
		case r == '_' || r == '-', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// Text renders a match for a terminal.
func (r Result) Text(c Call) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CALL     %s\n", Clean(describeCall(c)))
	fmt.Fprintf(&b, "VERDICT  %s\n", r.Verdict)
	switch r.Verdict {
	case VerdictDeny:
		b.WriteString("         a deny rule matches. Claude Code refuses the call; no hook or mode lifts a deny rule.\n")
	case VerdictAsk:
		b.WriteString("         an ask rule matches and no deny rule does. Claude Code prompts, even when an allow rule also matches.\n")
	case VerdictAllow:
		b.WriteString("         allow rules cover the whole call and no deny or ask rule matches.\n")
	case VerdictPartial:
		b.WriteString("         some subcommands are covered by allow rules and some are not (see below).\n")
	case VerdictNone:
		b.WriteString("         no rule matches. That is not \"allowed\" and not \"prompts\": the built-in read-only command set,\n")
		b.WriteString("         the permission mode, the classifier, hooks and the sandbox decide it, and none of them is a rule.\n")
	case VerdictUnknown:
		b.WriteString("         a rule that could change the answer cannot be evaluated here, so no lower decision is reported.\n")
	}
	for _, rule := range r.Rules {
		fmt.Fprintf(&b, "RULE     %s %s  (%s settings: %s)\n", rule.Decision, Clean(rule.Raw), rule.Source, Clean(rule.File))
	}
	for _, rule := range r.Unevaluated {
		fmt.Fprintf(&b, "UNKNOWN  %s %s  (%s settings: %s)\n", rule.Decision, Clean(rule.Raw), rule.Source, Clean(rule.File))
	}
	for _, cv := range r.Caveats {
		fmt.Fprintf(&b, "NOTE     %s\n", Clean(cv))
	}
	return b.String()
}

// describeCall is the call as the user wrote it, for echoing back.
func describeCall(c Call) string {
	for _, k := range [...]string{"command", "file_path", "notebook_path", "path", "url", "subagent_type", "skill"} {
		if v, ok := c.Input[k].(string); ok {
			return c.Tool + "(" + abbreviate(v) + ")"
		}
	}
	return c.Tool
}
