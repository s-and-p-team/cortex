package access

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Agent(Name), Skill(name) and Tool(param:value) rules (permissions, "Agent (subagents)",
// "Match by input parameter").

// primaryFields are each tool's primary content field. "You can't match a tool's primary
// content field this way ... Claude Code ignores it and emits a startup warning."
var primaryFields = map[string]bool{
	"command": true, "file_path": true, "path": true, "notebook_path": true, "url": true,
}

// documentedParams are parameters the docs name for a tool. A Tool(x:y) rule is a parameter
// rule when x is one of these or a field of the call; otherwise it is the tool's own specifier.
var documentedParams = map[string]map[string]bool{
	"Bash":  {"run_in_background": true, "dangerouslyDisableSandbox": true, "timeout": true},
	"Agent": {"model": true, "isolation": true, "subagent_type": true, "run_in_background": true},
}

// splitParam splits "name : value" at the first colon, trimming whitespace around both.
func splitParam(pattern string) (name, value string, ok bool) {
	i := strings.IndexByte(pattern, ':')
	if i <= 0 {
		return "", "", false
	}
	name, value = strings.TrimSpace(pattern[:i]), strings.TrimSpace(pattern[i+1:])
	if name == "" || strings.ContainsAny(name, " \t,.()") {
		return "", "", false
	}
	return name, value, true
}

// isParamRule reports whether pattern is a parameter rule for this call: "name:value" where
// name is a documented parameter of the tool or a field the call carries.
func isParamRule(tool, pattern string, c Call) (name, value string, ok bool) {
	name, value, ok = splitParam(pattern)
	if !ok {
		return "", "", false
	}
	if documentedParams[tool][name] || primaryFields[name] {
		return name, value, true
	}
	if _, has := c.Input[name]; has {
		return name, value, true
	}
	return "", "", false
}

// scalarText returns the literal text of a scalar JSON value, and false for an object, an array,
// null or an absent value (which a parameter rule never matches).
func scalarText(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case json.Number:
		return x.String(), true
	case float64:
		return fmt.Sprint(x), true
	}
	return "", false
}

// evaluateParam evaluates Tool(param:value). Deny and ask only: "an allow rule for one parameter
// value wouldn't establish that the call is safe overall".
func evaluateParam(r Rule, name, value string, c Call, res evalResult) evalResult {
	if primaryFields[name] {
		res.caveats = append(res.caveats, fmt.Sprintf(
			"%s: Claude Code ignores a parameter rule on a tool's primary content field (%s); use the tool's own specifier", r.Raw, name))
		return res
	}
	if r.Decision == Allow {
		res.caveats = append(res.caveats, r.Raw+": a parameter rule does nothing as an allow rule")
		return res
	}
	v, present := c.Input[name]
	if !present {
		return res // "A parameter the model omits is never matched."
	}
	text, scalar := scalarText(v)
	if !scalar {
		return res // nested objects and arrays are not matchable
	}
	if globMatch(value, text) {
		res.state = evalMatch
	}
	return res
}

// evaluateNamed evaluates Agent(Name) and Skill(name): an exact comparison with the field that
// names the thing being run.
func evaluateNamed(r Rule, pattern string, c Call, res evalResult) evalResult {
	field := "subagent_type"
	if r.Tool == "Skill" {
		field = "skill"
	}
	got, _ := c.Input[field].(string)
	if got == pattern {
		res.state = evalMatch
		return res
	}
	if r.Tool == "Skill" {
		res.caveats = append(res.caveats, "a Skill deny rule matches the skill under any of its names (an alias or display name), which this view cannot see")
	}
	return res
}
