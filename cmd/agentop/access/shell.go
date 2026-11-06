package access

import (
	"strings"
)

// This file splits a Bash command into the subcommands Claude Code's rules are matched
// against. It is NOT a shell parser. It recognises exactly what the permissions docs say the
// matcher is aware of:
//
//   - the separators && || ; | |& & and newline, outside quotes;
//   - commands nested inside $( ), backticks, ( ) subshells, { } groups, <( ) process
//     substitution and the bodies of for / while / until / if / case, because a deny or ask
//     rule applies to a command nested in any of them.
//
// What it cannot parse it says so (parsed.ok == false) and the caller reports the rule as
// unevaluable. It never guesses at a command it does not understand. Everything it is given is
// attacker-controlled, so it is a single linear scan with a hard cap on nesting.

const (
	// maxBashCommandLen: "Commands longer than 10,000 characters always prompt because they
	// exceed what the analysis parses."
	maxBashCommandLen = 10000
	// maxShellNesting bounds recursion into $( ) and friends.
	maxShellNesting = 32
)

// parsed is the result of splitting.
type parsed struct {
	ok bool
	// subs are the subcommands in order of appearance, nested ones after the command that
	// contains them. Each is trimmed and non-empty.
	subs []string
	// reason says why ok is false.
	reason string
}

// splitCommand splits cmd into its subcommands.
func splitCommand(cmd string) parsed {
	if len(cmd) > maxBashCommandLen {
		return parsed{reason: "the command is longer than 10,000 characters, which Claude Code does not analyse (it always prompts)"}
	}
	s := &splitter{src: cmd}
	s.scanList(0, "")
	if s.err != "" {
		return parsed{reason: s.err}
	}
	if s.i < len(s.src) {
		return parsed{reason: "unbalanced closing bracket"}
	}
	subs, reason := normaliseControlFlow(s.subs)
	if reason != "" {
		return parsed{reason: reason}
	}
	return parsed{ok: true, subs: subs}
}

// controlFlowOpeners and their closers. A subcommand such as "do rm x" is the command "rm x"
// introduced by a reserved word; the rule is matched against the command, not the keyword.
// Compound commands are balanced here so an unterminated "for ...; do ls" is reported
// unparseable rather than silently accepted.
var (
	flowOpeners = map[string]string{"for": "done", "while": "done", "until": "done", "select": "done", "if": "fi", "case": "esac"}
	// words that introduce a command inside a compound command
	flowLeaders = map[string]bool{"do": true, "then": true, "else": true, "elif": true, "!": true, "time": false}
)

func normaliseControlFlow(subs []string) ([]string, string) {
	var out []string
	var stack []string // the closers we still owe
	for _, sub := range subs {
		first, rest := firstWord(sub)
		switch {
		case flowOpeners[first] != "":
			stack = append(stack, flowOpeners[first])
			// "for x in a b" and "while cond": the header. For while/until/if/elif the rest of
			// the line IS a command (the condition); for/select/case headers are not.
			if first == "while" || first == "until" || first == "if" {
				if rest != "" {
					out = append(out, rest)
				}
			}
		case first == "done" || first == "fi" || first == "esac":
			if len(stack) == 0 || stack[len(stack)-1] != first {
				return nil, "a " + first + " with no matching opener"
			}
			stack = stack[:len(stack)-1]
			if rest != "" {
				out = append(out, rest) // e.g. "done > log" redirections: keep the tail as text
			}
		case flowLeaders[first]:
			if rest != "" {
				// "then if x" nests: handle the inner opener
				if f2, r2 := firstWord(rest); flowOpeners[f2] != "" {
					stack = append(stack, flowOpeners[f2])
					if (f2 == "while" || f2 == "until" || f2 == "if") && r2 != "" {
						out = append(out, r2)
					}
				} else {
					out = append(out, rest)
				}
			}
		case first == "in" || first == "elif" || first == "esac":
			if rest != "" {
				out = append(out, rest)
			}
		default:
			out = append(out, sub)
		}
	}
	if len(stack) > 0 {
		return nil, "an unterminated compound command (missing " + stack[len(stack)-1] + ")"
	}
	return out, ""
}

func firstWord(s string) (word, rest string) {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); i++ {
		if isBlank(s[i]) {
			return s[:i], strings.TrimSpace(s[i:])
		}
	}
	return s, ""
}

type splitter struct {
	src  string
	i    int
	subs []string
	err  string
	// budget bounds total work: every character is consumed once, but nested scans re-enter at
	// the same offset, so a counter makes the bound explicit rather than an argument.
	steps int
}

const maxSplitSteps = 4 * maxBashCommandLen

func (s *splitter) fail(msg string) {
	if s.err == "" {
		s.err = msg
	}
}

// scanList reads a list of commands until the closer (")" "}" "`" or "" for end of input) and
// consumes the closer. Each command's text is emitted as one subcommand, followed by whatever
// commands were nested inside it.
func (s *splitter) scanList(depth int, closer string) {
	if depth > maxShellNesting {
		s.fail("commands are nested too deeply to analyse")
		return
	}
	var cur strings.Builder
	var nested []string
	// pendingOp is true after && or || until a command follows: "&&" with nothing after it makes
	// the whole command unparseable.
	pendingOp := false
	hadCommand := false

	flush := func() {
		text := strings.TrimSpace(cur.String())
		cur.Reset()
		if text != "" {
			s.subs = append(s.subs, text)
			s.subs = append(s.subs, nested...)
			hadCommand = true
			pendingOp = false
		} else if len(nested) > 0 {
			s.subs = append(s.subs, nested...)
			hadCommand = true
			pendingOp = false
		}
		nested = nested[:0]
	}

	for s.i < len(s.src) && s.err == "" {
		if s.steps++; s.steps > maxSplitSteps {
			s.fail("the command is too complex to analyse")
			return
		}
		c := s.src[s.i]

		// the closer of the enclosing construct
		if closer != "" && s.atCloser(closer) {
			flush()
			if pendingOp {
				s.fail("a command ends with && or || and nothing after it")
			}
			s.i += len(closer)
			return
		}

		switch c {
		case '\\':
			if s.i+1 >= len(s.src) {
				s.fail("the command ends in a backslash")
				return
			}
			cur.WriteByte(c)
			cur.WriteByte(s.src[s.i+1])
			s.i += 2

		case '\'':
			start := s.i
			s.i++
			end := strings.IndexByte(s.src[s.i:], '\'')
			if end < 0 {
				s.fail("an unterminated single quote")
				return
			}
			s.i += end + 1
			cur.WriteString(s.src[start:s.i])

		case '"':
			start := s.i
			s.i++
			s.scanDouble(depth, &nested)
			cur.WriteString(s.src[start:min(s.i, len(s.src))])

		case '`':
			start := s.i
			s.i++
			s.scanList(depth+1, "`")
			// The nested commands were appended to s.subs by the inner call; hoist them so they
			// follow the command that contains them.
			nested = append(nested, s.takeNestedSince(&cur, start)...)
			cur.WriteString(s.src[start:min(s.i, len(s.src))])

		case '$':
			switch {
			case s.peek("$(("):
				// arithmetic: not a command. Skip to the matching "))".
				start := s.i
				s.i += 3
				if !s.skipUntil("))") {
					s.fail("an unterminated arithmetic expansion")
					return
				}
				cur.WriteString(s.src[start:s.i])
			case s.peek("$("):
				start := s.i
				s.i += 2
				before := len(s.subs)
				s.scanList(depth+1, ")")
				nested = append(nested, s.subs[before:]...)
				s.subs = s.subs[:before]
				cur.WriteString(s.src[start:min(s.i, len(s.src))])
			case s.peek("${"):
				start := s.i
				s.i += 2
				if !s.skipUntil("}") {
					s.fail("an unterminated ${ expansion")
					return
				}
				cur.WriteString(s.src[start:s.i])
			case s.peek("$'"):
				start := s.i
				s.i += 2
				if !s.skipANSIC() {
					s.fail("an unterminated $'...' string")
					return
				}
				cur.WriteString(s.src[start:s.i])
			default:
				cur.WriteByte(c)
				s.i++
			}

		case '<', '>':
			if (c == '<' || c == '>') && s.i+1 < len(s.src) && s.src[s.i+1] == '(' {
				// process substitution: a command list in its own right
				start := s.i
				s.i += 2
				before := len(s.subs)
				s.scanList(depth+1, ")")
				nested = append(nested, s.subs[before:]...)
				s.subs = s.subs[:before]
				cur.WriteString(s.src[start:min(s.i, len(s.src))])
				continue
			}
			cur.WriteByte(c)
			s.i++

		case '(':
			// a subshell: its commands are subcommands. It is not part of the current command's
			// text, so the text before it (usually nothing) is flushed first.
			flush()
			s.i++
			before := len(s.subs)
			s.scanList(depth+1, ")")
			// the inner commands are already in order in s.subs
			_ = before
			hadCommand = true
			pendingOp = false

		case '{':
			// A brace group only when it is a standalone word ({ then whitespace): "{a,b}" and
			// "${x}" are expansions, handled above or left as text.
			if cur.Len() == 0 && s.i+1 < len(s.src) && isBlank(s.src[s.i+1]) {
				s.i++
				s.scanList(depth+1, "}")
				hadCommand = true
				pendingOp = false
				continue
			}
			cur.WriteByte(c)
			s.i++

		case ')', '}':
			// A closer with no opener (we were not given it as ours).
			if c == ')' {
				s.fail("an unbalanced closing parenthesis")
				return
			}
			cur.WriteByte(c)
			s.i++

		case ';', '\n':
			flush()
			s.i++
			// a ";;" case terminator and similar leave nothing to flush

		case '&':
			switch {
			case s.peek("&&"):
				if strings.TrimSpace(cur.String()) == "" && len(nested) == 0 && !hadCommand {
					s.fail("a command starts with &&")
					return
				}
				flush()
				pendingOp = true
				s.i += 2
			default:
				flush()
				s.i++
				if s.peek("&") { // can't happen (handled above), kept for clarity
					s.i++
				}
			}

		case '|':
			switch {
			case s.peek("||"):
				if strings.TrimSpace(cur.String()) == "" && len(nested) == 0 && !hadCommand {
					s.fail("a command starts with ||")
					return
				}
				flush()
				pendingOp = true
				s.i += 2
			case s.peek("|&"):
				flush()
				s.i += 2
			default:
				flush()
				s.i++
			}

		default:
			cur.WriteByte(c)
			s.i++
		}
	}

	if s.err != "" {
		return
	}
	if closer != "" {
		s.fail("an unterminated " + describeCloser(closer))
		return
	}
	flush()
	if pendingOp {
		s.fail("a command ends with && or || and nothing after it")
	}
}

// takeNestedSince is a no-op placeholder kept for the backtick case: the inner scan has already
// appended its commands to s.subs in order, and they must precede the enclosing command's text,
// which is emitted at the next flush. Moving them out keeps the "nested after the containing
// command" ordering the other constructs have.
func (s *splitter) takeNestedSince(_ *strings.Builder, _ int) []string { return nil }

// scanDouble reads the inside of a double-quoted string, whose opening quote is consumed. Only
// $( ), backticks and the closing quote are special; everything else, including && and ;, is
// text. Nested commands are appended to *nested.
func (s *splitter) scanDouble(depth int, nested *[]string) {
	for s.i < len(s.src) && s.err == "" {
		if s.steps++; s.steps > maxSplitSteps {
			s.fail("the command is too complex to analyse")
			return
		}
		switch c := s.src[s.i]; {
		case c == '\\':
			if s.i+1 >= len(s.src) {
				s.fail("an unterminated double quote")
				return
			}
			s.i += 2
		case c == '"':
			s.i++
			return
		case c == '$' && s.peek("$(("):
			s.i += 3
			if !s.skipUntil("))") {
				s.fail("an unterminated arithmetic expansion")
				return
			}
		case c == '$' && s.peek("$("):
			s.i += 2
			before := len(s.subs)
			s.scanList(depth+1, ")")
			*nested = append(*nested, s.subs[before:]...)
			s.subs = s.subs[:before]
		case c == '`':
			s.i++
			before := len(s.subs)
			s.scanList(depth+1, "`")
			*nested = append(*nested, s.subs[before:]...)
			s.subs = s.subs[:before]
		default:
			s.i++
		}
	}
	if s.err == "" {
		s.fail("an unterminated double quote")
	}
}

func (s *splitter) peek(p string) bool { return strings.HasPrefix(s.src[s.i:], p) }

// atCloser reports whether the closer starts here. A ")" closes only at the current level; a
// "}" closes only as a standalone word.
func (s *splitter) atCloser(closer string) bool {
	if !s.peek(closer) {
		return false
	}
	if closer == "}" {
		// "}" ends a group only when it follows ; or a newline or whitespace and is a word.
		return s.i == 0 || isBlank(s.src[s.i-1]) || s.src[s.i-1] == ';' || s.src[s.i-1] == '\n'
	}
	return true
}

// skipUntil advances past the first occurrence of end, reporting whether it was found.
func (s *splitter) skipUntil(end string) bool {
	k := strings.Index(s.src[s.i:], end)
	if k < 0 {
		s.i = len(s.src)
		return false
	}
	s.i += k + len(end)
	return true
}

// skipANSIC advances past a $'...' string, whose backslash escapes may include \'.
func (s *splitter) skipANSIC() bool {
	for s.i < len(s.src) {
		switch s.src[s.i] {
		case '\\':
			s.i += 2
		case '\'':
			s.i++
			return true
		default:
			s.i++
		}
	}
	return false
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' || c == '\n' }

func describeCloser(c string) string {
	switch c {
	case ")":
		return "parenthesis"
	case "}":
		return "brace group"
	case "`":
		return "backtick substitution"
	}
	return "construct"
}

// --- wrappers --------------------------------------------------------------------------------

// stripWrappers removes, from the front of one subcommand, the fixed set of wrappers Claude
// Code strips before matching a Bash rule: timeout, time, nice, nohup, stdbuf, command,
// builtin, noglob, flagless xargs, and leading environment assignments. It reports whether an
// assignment was removed, because an allow rule may not match past an assignment of an
// arbitrary variable while a deny or ask rule may.
//
// Not stripped (the docs say so): the query form `command -v`, zsh's nocorrect, `xargs` with
// flags, exec wrappers (watch, setsid, ionice, flock) and environment runners (npx,
// docker exec, devbox run, direnv exec, mise exec).
func stripWrappers(cmd string) (rest string, assigned bool) {
	rest, names := stripWrappersNamed(cmd)
	return rest, len(names) > 0
}

// stripWrappersNamed is stripWrappers, also returning the names of the environment variables
// whose leading assignments it removed.
func stripWrappersNamed(cmd string) (rest string, assigned []string) {
	rest = strings.TrimSpace(cmd)
	for guard := 0; guard < 64; guard++ {
		fields := splitWords(rest)
		if len(fields) == 0 {
			return rest, assigned
		}
		w := fields[0]

		if isAssignment(w) {
			rest = strings.TrimSpace(rest[len(w):])
			assigned = append(assigned, w[:strings.IndexByte(w, '=')])
			continue
		}
		switch w {
		case "timeout":
			// timeout [flags] DURATION command...
			i := 1
			for i < len(fields) && strings.HasPrefix(fields[i], "-") {
				i++
				// -s SIGNAL and -k DURATION take a value
				if (fields[i-1] == "-s" || fields[i-1] == "-k" || fields[i-1] == "--signal" || fields[i-1] == "--kill-after") && i < len(fields) {
					i++
				}
			}
			if i >= len(fields) {
				return rest, assigned
			}
			i++ // the DURATION
			if i > len(fields) {
				return rest, assigned
			}
			rest = restAfter(rest, fields, i)
		case "time", "nohup", "builtin", "noglob":
			rest = restAfter(rest, fields, 1)
		case "command":
			if len(fields) > 1 && (fields[1] == "-v" || fields[1] == "-V" || fields[1] == "-p" && false) {
				return rest, assigned // the query form looks a command up; it does not run one
			}
			rest = restAfter(rest, fields, 1)
		case "nice":
			i := 1
			if i < len(fields) && fields[i] == "-n" {
				i += 2
			} else if i < len(fields) && strings.HasPrefix(fields[i], "-") {
				i++
			}
			if i > len(fields) {
				return rest, assigned
			}
			rest = restAfter(rest, fields, i)
		case "stdbuf":
			i := 1
			for i < len(fields) && strings.HasPrefix(fields[i], "-") {
				i++
			}
			rest = restAfter(rest, fields, i)
		case "xargs":
			if len(fields) > 1 && strings.HasPrefix(fields[1], "-") {
				return rest, assigned // xargs with flags is matched as an xargs command
			}
			rest = restAfter(rest, fields, 1)
		default:
			return rest, assigned
		}
		if strings.TrimSpace(rest) == "" {
			return "", assigned
		}
	}
	return rest, assigned
}

// restAfter returns cmd with its first n whitespace-separated words removed.
func restAfter(cmd string, fields []string, n int) string {
	if n >= len(fields) {
		return ""
	}
	s := strings.TrimSpace(cmd)
	for k := 0; k < n; k++ {
		s = strings.TrimSpace(s[len(fields[k]):])
	}
	return s
}

// isAssignment reports whether w is NAME=value with a valid shell identifier before the "=".
func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := w[i]
		switch {
		case c == '_', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// splitWords splits on blanks outside quotes. It is for the wrapper prefix only: it keeps
// quoted words whole so `FOO="a b" rm x` strips the assignment as one word.
func splitWords(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && isBlank(s[i]) {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && !isBlank(s[i]) {
			switch s[i] {
			case '\'':
				if k := strings.IndexByte(s[i+1:], '\''); k >= 0 {
					i += k + 2
					continue
				}
			case '"':
				j := i + 1
				for j < len(s) && s[j] != '"' {
					if s[j] == '\\' {
						j++
					}
					j++
				}
				if j < len(s) {
					i = j + 1
					continue
				}
			case '\\':
				i++
			}
			i++
		}
		out = append(out, s[start:min(i, len(s))])
	}
	return out
}

// safeAssignments are the leading environment assignments an ALLOW rule may match past. The
// docs say "certain known-safe environment variables" and do not list them; the only one they
// name is NODE_ENV, in the example `Bash(npm test *)` matches `NODE_ENV=test npm test`. Nothing
// else is assumed safe: a missing entry makes the result more cautious (none or partial),
// which is the safe direction, and a caveat says why.
var safeAssignments = map[string]bool{"NODE_ENV": true}

// onlySafeAssignments reports whether every assigned variable is one an allow rule may see past.
func onlySafeAssignments(names []string) bool {
	for _, n := range names {
		if !safeAssignments[n] {
			return false
		}
	}
	return true
}
