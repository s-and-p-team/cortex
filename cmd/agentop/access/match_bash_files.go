package access

import (
	"fmt"
	"path"
	"strings"
)

// Read(path) and Edit(path) deny and ask rules also apply to the files a Bash command names.
//
// The docs: "Read and Edit deny rules apply to Claude's built-in file tools, to file commands
// Claude Code recognizes in Bash, such as cat, head, tail, sed, and tee, and to the targets of
// Bash redirections such as > file and < file." The set of recognized commands is not listed, and
// one recorded session shows grep is in it: two commands were rejected with ruleSource
// userSettings because Read(.env) and Read(.env.*) guarded a file named to grep.
//
// So the rule here is deliberately wider than the docs' examples, in the safe direction. Any
// literal word of a subcommand, and any redirection target, is treated as a possible file. If a
// Read or Edit deny or ask rule covers it, the Bash call's verdict is unknown: a rule might have
// refused it, and this view cannot tell which commands count as "file commands". The cost is a
// few unknowns for commands that merely mention a guarded name (echo .env); the alternative is
// reporting `none` for a command Claude Code rejected, which is the error that matters.
//
// What is NOT done: variables, globs and substitutions are not expanded, so a command that builds
// its file argument is checked on its literal words and says so.

const (
	// maxFileWords bounds how many words of one command are checked against the rules. A command
	// with more is reported unknown rather than truncated: dropping words hides a guarded file.
	maxFileWords = 512
)

// bashFileWords returns the words of a Bash command that could name a file, across all its
// subcommands: arguments after the program name that are not options, and redirection targets.
// skipped reports that some word was left out because it is built from an expansion ($VAR, a
// glob, a substitution). ok is false for a command that cannot be split.
func bashFileWords(cmd string) (words []string, skipped bool, ok bool) {
	p := splitCommand(cmd)
	if !p.ok {
		return nil, false, false
	}
	for _, sub := range p.subs {
		stripped, _ := stripWrappersNamed(sub)
		ws := splitWords(stripped)
		for i := 0; i < len(ws); i++ {
			w := ws[i]
			// redirections: >file, >>file, <file, 2>file, &>file, and the spaced forms
			if tgt, consumed, isRedir := redirectTarget(w, ws, i); isRedir {
				i += consumed
				if tgt != "" {
					words, skipped = addWord(words, skipped, tgt)
				}
				continue
			}
			if i == 0 { // the program
				continue
			}
			if strings.HasPrefix(w, "-") {
				continue
			}
			words, skipped = addWord(words, skipped, w)
		}
	}
	return words, skipped, true
}

// redirectTarget recognises a redirection word and returns its target. consumed is how many
// FOLLOWING words it used (1 for the spaced form "> file").
func redirectTarget(w string, ws []string, i int) (target string, consumed int, ok bool) {
	op := w
	rest := ""
	// strip a leading fd or &: 2> &> 1>>
	j := 0
	for j < len(w) && (w[j] >= '0' && w[j] <= '9' || w[j] == '&') {
		j++
	}
	body := w[j:]
	switch {
	case strings.HasPrefix(body, ">>"):
		op, rest = w[:j]+">>", body[2:]
	case strings.HasPrefix(body, ">|"):
		op, rest = w[:j]+">|", body[2:]
	case strings.HasPrefix(body, ">&"), strings.HasPrefix(body, "<&"):
		return "", 0, true // fd duplication, not a file
	case strings.HasPrefix(body, ">"), strings.HasPrefix(body, "<"):
		op, rest = w[:j]+body[:1], body[1:]
	default:
		return "", 0, false
	}
	_ = op
	if rest != "" {
		return rest, 0, true
	}
	if i+1 < len(ws) {
		return ws[i+1], 1, true
	}
	return "", 0, true
}

// addWord unquotes a word and records it, or marks it skipped when it is built from an
// expansion this view does not perform.
func addWord(words []string, skipped bool, w string) ([]string, bool) {
	if len(words) >= maxFileWords+1 {
		return words, skipped
	}
	u, literal := unquoteWord(w)
	if !literal {
		return words, true
	}
	if u == "" {
		return words, skipped
	}
	return append(words, u), skipped
}

// unquoteWord removes quoting from a word and reports whether it is a literal: no variable, glob
// or substitution that would make the real file name differ from the text.
func unquoteWord(w string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(w); i++ {
		switch c := w[i]; c {
		case '\'':
			k := strings.IndexByte(w[i+1:], '\'')
			if k < 0 {
				return "", false
			}
			b.WriteString(w[i+1 : i+1+k])
			i += k + 1
		case '"':
			j := i + 1
			for j < len(w) && w[j] != '"' {
				if w[j] == '\\' && j+1 < len(w) {
					j++
				}
				if w[j] == '$' || w[j] == '`' {
					return "", false
				}
				b.WriteByte(w[j])
				j++
			}
			i = j
		case '\\':
			if i+1 < len(w) {
				i++
				b.WriteByte(w[i])
			}
		case '$', '`', '*', '?', '[', '~':
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// fileRuleGuards returns the Read and Edit deny and ask rules of the policy, which are the ones
// that can refuse a Bash command because of a file it names.
func fileRuleGuards(rules []Rule) []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Decision == Allow || r.Ignored != "" || !pathRuleFamily(r.Tool) {
			continue
		}
		_, pat := matchKey(r.Tool, r.Pattern)
		if pat == "" || pat == "*" {
			continue // a bare Read/Edit rule is about the TOOL, not about a file named in a command
		}
		out = append(out, r)
	}
	return out
}

// bashNamedFileGuard looks for a Read or Edit deny or ask rule that covers a file the command
// names. It returns the rules it found, the rules it could not evaluate, and the caveats.
func bashNamedFileGuard(rules []Rule, c Call, ctx MatchContext) (found, unevaluable []Rule, caveats []string) {
	guards := fileRuleGuards(rules)
	if len(guards) == 0 {
		return nil, nil, nil
	}
	cmd, has := bashCommand(c)
	if !has {
		return nil, nil, nil
	}
	words, skipped, ok := bashFileWords(cmd)
	if !ok {
		return nil, nil, nil // an unparseable command is already unknown through the Bash rules
	}
	if len(words) > maxFileWords {
		return guards, nil, []string{fmt.Sprintf("the command names too many words (over %d) to check each against the file rules, so a guarded file cannot be ruled out", maxFileWords)}
	}
	if skipped {
		caveats = append(caveats, "part of the command is built from a variable or glob, so the files it names cannot be checked against the Read and Edit rules")
	}
	seen := map[string]bool{}
	for _, g := range guards {
		_, pat := matchKey(g.Tool, g.Pattern)
		for _, w := range words {
			fc := Call{Tool: g.Tool, Input: map[string]any{"file_path": w}}
			if g.Tool == "Edit" {
				fc.Input["file_path"] = w
			}
			res := evaluatePath(g, pat, fc, ctx, evalResult{})
			if res.state == evalUnknown && !seen[g.Raw+"?"] {
				seen[g.Raw+"?"] = true
				unevaluable = append(unevaluable, g)
				caveats = append(caveats, res.caveats...)
				continue
			}
			if res.state == evalMatch && !seen[g.Raw] {
				seen[g.Raw] = true
				found = append(found, g)
			}
		}
	}
	if len(found) > 0 || len(unevaluable) > 0 {
		caveats = append(caveats, "the command names a file that a Read or Edit rule covers; Claude Code applies those rules to the file commands it recognizes inside Bash, a set it does not list, so this view cannot say whether it was refused")
	}
	return found, unevaluable, caveats
}

// cleanWord is for tests and diagnostics: the path form of a word.
func cleanWord(w string) string { return path.Clean(w) }
