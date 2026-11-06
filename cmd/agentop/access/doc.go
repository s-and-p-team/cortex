// Package access resolves the effective Claude Code permission policy for a
// working directory from its settings files, with the file each rule and
// setting came from.
//
// It is a pure function of its Input: it reads only through Input.FS, never
// writes, never touches the network, and imports nothing from the TUI. The
// `agentop access` command and, later, the viewer's access pane are thin
// layers over Resolve.
//
// # Rules this package implements
//
// Verified 2026-11-06 against code.claude.com/docs (settings, permissions,
// managed-settings, settings-reference). When Claude Code's documented
// behaviour changes, change this comment, the spec
// (docs/superpowers/specs/2026-11-06-agentop-access-view-design.md) and the
// tests together.
//
// Layers, highest precedence first:
//
//  1. Managed. File sources only: managed-settings.json, then every *.json in
//     managed-settings.d/ in alphabetical order, in /Library/Application
//     Support/ClaudeCode (macOS) or /etc/claude-code (Linux, WSL). MDM,
//     registry and claude.ai-console delivery are not files and cannot be read
//     here; the layer reports "file sources only".
//  2. Command line: --settings <file-or-json>. Other flags (--permission-mode,
//     --allowedTools) are per-session inputs that are not recoverable from
//     disk and are not modelled.
//  3. Project local: .claude/settings.local.json. Since Claude Code v2.1.211
//     this lives at the git repository root when the session started in a
//     subdirectory, and a copy left in the starting directory by older
//     versions is still read; rules from both apply. It stays beside the
//     starting directory when there is no git repo or the root is the home
//     directory.
//  4. Shared project: .claude/settings.json in the session's primary working
//     directory only.
//  5. User: settings.json in the config directory (CLAUDE_CONFIG_DIR, else
//     ~/.claude).
//
// Merging:
//
//   - permissions.allow, ask, deny and additionalDirectories merge across
//     layers. Evaluation order is deny, then ask, then allow; the first match
//     wins regardless of layer or specificity.
//   - Scalars (permissions.defaultMode, sandbox.enabled) take the highest layer
//     that sets them. A defaultMode of "auto" or "bypassPermissions" does not
//     take effect from project or local settings.
//   - With allowManagedPermissionRulesOnly set in managed settings, allow, ask
//     and deny rules from every other layer are ignored.
//   - Project allow rules and additionalDirectories wait for workspace trust,
//     which is not in any settings file; they are flagged, not asserted.
//
// Only permissions, sandbox.enabled and a count of hooks are read from a
// settings file. Everything else, including env, is dropped at decode so a
// secret in a settings file cannot reach any output.
package access
