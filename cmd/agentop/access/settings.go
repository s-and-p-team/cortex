package access

import (
	"encoding/json"
	"strings"
)

// settingsDoc is the only part of a settings file this package decodes.
// Everything else, env above all, is dropped here so a secret in a settings
// file cannot reach any output.
type settingsDoc struct {
	AllowManagedPermissionRulesOnly bool `json:"allowManagedPermissionRulesOnly"`
	Permissions                     struct {
		Allow                 []string `json:"allow"`
		Ask                   []string `json:"ask"`
		Deny                  []string `json:"deny"`
		DefaultMode           string   `json:"defaultMode"`
		AdditionalDirectories []string `json:"additionalDirectories"`
		// DisableBypassPermissionsMode is "disable" to lock bypassPermissions out.
		DisableBypassPermissionsMode string `json:"disableBypassPermissionsMode"`
	} `json:"permissions"`
	Sandbox struct {
		Enabled *bool `json:"enabled"`
	} `json:"sandbox"`
	// Hooks is keyed by event name. The registrations themselves are opaque:
	// only which events have any is reported.
	Hooks map[string]json.RawMessage `json:"hooks"`
}

func decodeSettings(data []byte) (*settingsDoc, error) {
	var d settingsDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// parseRule splits "Tool(specifier)" into its tool and specifier. Parentheses
// inside the specifier are literal. A string that is not of that shape, such
// as an unterminated "Bash(", is returned whole as the tool: it is shown, not
// guessed at.
func parseRule(raw string) (tool, pattern string) {
	i := strings.IndexByte(raw, '(')
	if i <= 0 || !strings.HasSuffix(raw, ")") {
		return raw, ""
	}
	return raw[:i], raw[i+1 : len(raw)-1]
}

// matchKey normalises a rule so that two spellings of the same Bash rule
// compare equal: Bash(*) is the bare tool, and a trailing ":*" is a trailing
// " *". A pattern of "" means every use of the tool.
func matchKey(tool, pattern string) (string, string) {
	if tool == "Bash" {
		if pattern == "*" {
			pattern = ""
		}
		if strings.HasSuffix(pattern, ":*") {
			pattern = strings.TrimSuffix(pattern, ":*") + " *"
		}
	}
	return tool, pattern
}
