package access

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Verdict is what the rules say about one tool call. It is a statement about RULES, never about
// what Claude Code finally did: the built-in read-only command set, the permission mode, the
// classifier, hooks, the sandbox and workspace trust all decide outcomes that no rule states.
type Verdict int

const (
	// VerdictNone: no rule matches. NOT "allowed" and NOT "prompts": the read-only command set,
	// the mode, the classifier and the rest decide that.
	VerdictNone Verdict = iota
	// VerdictDeny: a deny rule matches. Claude Code refuses the call; no hook or mode lifts a
	// deny rule.
	VerdictDeny
	// VerdictAsk: an ask rule matches and no deny rule does. Claude Code prompts, even when an
	// allow rule also matches.
	VerdictAsk
	// VerdictAllow: allow rules cover the whole call, and no deny or ask rule matches.
	VerdictAllow
	// VerdictPartial: Bash only. Some subcommands are covered by allow rules and others are not;
	// the rest depend on the read-only set, the mode and the classifier.
	VerdictPartial
	// VerdictUnknown: a rule that could outrank every lower decision cannot be evaluated here,
	// so no lower decision is reported past it.
	VerdictUnknown
)

func (v Verdict) String() string {
	switch v {
	case VerdictNone:
		return "none"
	case VerdictDeny:
		return "deny"
	case VerdictAsk:
		return "ask"
	case VerdictAllow:
		return "allow"
	case VerdictPartial:
		return "partial"
	}
	return "unknown"
}

func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// Call is one tool call: the tool's name and its decoded JSON input.
type Call struct {
	Tool  string
	Input map[string]any
}

// MatchContext is what the path rules need to anchor a pattern. Empty means unknown, and a rule
// that needs an unknown anchor is reported unevaluable rather than guessed.
type MatchContext struct {
	// Cwd is the session's primary working directory.
	Cwd string
	// Home is the user's home directory.
	Home string
	// ConfigDir is the Claude config directory (where user settings live).
	ConfigDir string
}

// Result is the answer for one call.
type Result struct {
	Verdict Verdict `json:"verdict"`
	// Rules are the rules that decided the verdict.
	Rules []Rule `json:"rules"`
	// Unevaluated are rules that could not be evaluated for this call: the answer is only as
	// good as the claim that they would not have changed it.
	Unevaluated []Rule `json:"unevaluated"`
	// Caveats are conditions on the answer, in words.
	Caveats []string `json:"caveats"`
}

// evalState is how one rule relates to one call.
type evalState int

const (
	evalNoMatch evalState = iota
	evalMatch
	// evalUnknown: the rule cannot be evaluated for this call.
	evalUnknown
)

// evalResult is the outcome of evaluating one rule against one call.
type evalResult struct {
	state   evalState
	caveats []string
}

// Match says which of the policy's rules apply to c.
//
// Rules are examined deny, then ask, then allow, whatever order they are stored in or which
// layer they came from: that is Claude Code's evaluation order, and the first decision with a
// matching rule wins. Ignored rules (voided by managed policy) are skipped.
//
// The one thing it will not do is report a lower decision past a higher rule it could not
// evaluate: an unevaluable deny might be the deny. An unevaluable ALLOW can only ever have
// allowed, so it cannot raise the answer and leaves a caveat.
func (p Policy) Match(c Call, ctx MatchContext) Result {
	res := Result{Verdict: VerdictNone, Rules: []Rule{}, Unevaluated: []Rule{}, Caveats: []string{}}
	addCaveat := func(s string) {
		for _, have := range res.Caveats {
			if have == s {
				return
			}
		}
		res.Caveats = append(res.Caveats, s)
	}

	for _, d := range [...]Decision{Deny, Ask, Allow} {
		var matched, unknown []Rule
		for _, r := range p.Rules {
			if r.Decision != d || r.Ignored != "" {
				continue
			}
			e := evaluate(r, c, ctx)
			for _, cv := range e.caveats {
				addCaveat(cv)
			}
			switch e.state {
			case evalMatch:
				matched = append(matched, r)
			case evalUnknown:
				unknown = append(unknown, r)
			}
		}

		switch {
		case d == Allow:
			res.Unevaluated = append(res.Unevaluated, unknown...)
			if len(matched) > 0 {
				res.Verdict, res.Rules = VerdictAllow, matched
				needTrust := true
				for _, r := range matched {
					needTrust = needTrust && r.NeedsTrust
				}
				if needTrust {
					addCaveat("this allow rule is in the shared project file, so it applies only after the folder is trusted")
				}
				return res
			}
			if len(unknown) > 0 {
				addCaveat(fmt.Sprintf("%d allow rule(s) could not be evaluated; they could only have allowed this call", len(unknown)))
			}
			return res
		case len(matched) > 0:
			// A rule of this decision matched, so lower decisions are irrelevant. An unevaluated
			// rule of the SAME decision changes nothing either: the decision is already this one.
			res.Verdict, res.Rules = verdictOf(d), matched
			res.Unevaluated = append(res.Unevaluated, unknown...)
			return res
		case len(unknown) > 0:
			res.Verdict, res.Unevaluated = VerdictUnknown, unknown
			addCaveat(fmt.Sprintf("a %s rule could not be evaluated, so no lower decision is reported", d))
			return res
		}
	}
	return res
}

func verdictOf(d Decision) Verdict {
	switch d {
	case Deny:
		return VerdictDeny
	case Ask:
		return VerdictAsk
	}
	return VerdictAllow
}

// --- tool calls from the wire ---------------------------------------------------------------

// MaxCallInputBytes bounds a tool call's JSON arguments. The largest real input measured was
// 45 KB; a megabyte is far past anything legitimate, and the matcher runs on every row.
const MaxCallInputBytes = 1 << 20

// maxCallInputDepth bounds JSON nesting, so the refusal is ours and typed.
const maxCallInputDepth = 64

// ErrInputTooLarge is returned for arguments over MaxCallInputBytes.
var ErrInputTooLarge = errors.New("tool input is too large to match")

// CallFromJSON decodes a tool call's arguments, as the inference parser records them: a JSON
// object in a string. Numbers keep their literal text, because a parameter rule compares what
// Claude sent and a float64 would rewrite 12345678901234567890. Empty arguments, "null" and
// "{}" are a call with no input; anything that is not a single JSON object is an error.
func CallFromJSON(tool, args string) (Call, error) {
	c := Call{Tool: tool, Input: map[string]any{}}
	if len(args) > MaxCallInputBytes {
		return c, ErrInputTooLarge
	}
	b := bytes.TrimSpace([]byte(args))
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return c, nil
	}
	if jsonDepth(b) > maxCallInputDepth {
		return c, fmt.Errorf("tool input is nested deeper than %d levels", maxCallInputDepth)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return c, fmt.Errorf("tool input is not JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return c, errors.New("tool input has trailing data after the JSON value")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return c, errors.New("tool input is not a JSON object")
	}
	c.Input = m
	return c, nil
}

// jsonDepth returns the maximum bracket nesting of b, ignoring brackets inside strings. It is a
// single pass, so a hostile input costs one scan.
func jsonDepth(b []byte) int {
	d, deepest := 0, 0
	inStr, esc := false, false
	for _, c := range b {
		switch {
		case esc:
			esc = false
		case inStr:
			if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{' || c == '[':
			if d++; d > deepest {
				deepest = d
			}
		case c == '}' || c == ']':
			d--
		}
	}
	return deepest
}
