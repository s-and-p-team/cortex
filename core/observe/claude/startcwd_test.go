package claude

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readOne harvests a single transcript made of lines and returns its entry.
func readOne(t *testing.T, lines ...string) SessionMetadata {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "claude")
	writeSessionTranscript(t, filepath.Join(cfg, "projects", "-p"), "s1.jsonl", lines...)
	got, _, _, err := ReadSessions(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := got["s1"]
	if !ok {
		t.Fatalf("no entry for s1 in %v", got)
	}
	return m
}

// The session's working directory is where it STARTED: Claude Code reads project settings from
// the primary working directory, and the project directory a transcript is filed under is named
// for it. Measured on 96 real transcripts the first cwd matched that name in 96 and the last in
// 62, because a Bash `cd` moves the cwd a line records without moving the session.
func TestReadSessions_RecordsTheStartingCwdNotTheLastOne(t *testing.T) {
	m := readOne(t,
		`{"type":"system","cwd":"/w/start"}`,
		`{"type":"system","cwd":"/w/start/sub"}`,
		`{"type":"system","cwd":"/w/other"}`)
	if m.Cwd != "/w/start" {
		t.Errorf("Cwd = %q, want the first, /w/start", m.Cwd)
	}
	// The title fallback is a different question and keeps its last-wins rule.
	if m.Title != "/w/other" {
		t.Errorf("Title = %q, want the last cwd, /w/other: the fallback must not change", m.Title)
	}
}

// A path is an identifier, not prose: the title path collapses whitespace and drops markup, which
// would turn "/Users/me/My  Project" into a different directory and show another tree's policy.
func TestReadSessions_CwdIsKeptVerbatim(t *testing.T) {
	const p = "/Users/me/My  Project/<x> y/ünï"
	b, _ := json.Marshal(map[string]string{"type": "system", "cwd": p})
	if m := readOne(t, string(b)); m.Cwd != p {
		t.Errorf("Cwd = %q, want %q unchanged", m.Cwd, p)
	}
}

func TestReadSessions_AnUnusableCwdIsDroppedNotRepaired(t *testing.T) {
	// Raw JSON string bodies, as a transcript would hold them: a Go literal cannot spell a lone
	// surrogate, and the escapes are what a hostile file actually contains.
	for name, body := range map[string]string{
		"relative":           `proj/x`,
		"empty":              ``,
		"newline":            `/a\nb`,
		"NUL":                `/a\u0000b`,
		"ESC":                `/a\u001b[31mb`,
		"bidi override":      `/a\u202eb`,
		"line separator":     `/a\u2028b`,
		"lone surrogate":     `/a\ud800b`,
		"longer than a path": "/" + strings.Repeat("a", 5000),
	} {
		t.Run(name, func(t *testing.T) {
			line := `{"type":"system","cwd":"` + body + `"}`
			if m := readOne(t, line); m.Cwd != "" {
				t.Errorf("Cwd = %q, want it dropped: a repaired path names a different directory", m.Cwd)
			}
		})
	}
}

func TestReadSessions_TheFirstUsableCwdWins(t *testing.T) {
	m := readOne(t,
		`{"type":"system","cwd":"relative"}`,
		`{"type":"system","cwd":"/w/good"}`,
		`{"type":"system","cwd":"/w/later"}`)
	if m.Cwd != "/w/good" {
		t.Errorf("Cwd = %q, want /w/good", m.Cwd)
	}
}

func TestReadSessions_CwdIsCleaned(t *testing.T) {
	if m := readOne(t, `{"type":"system","cwd":"/w/proj/"}`); m.Cwd != "/w/proj" {
		t.Errorf("Cwd = %q, want the trailing slash removed", m.Cwd)
	}
}

// The mode the session is running in, which is not the configured default: it changes with
// Shift+Tab and --permission-mode. Measured, 13 of 94 transcripts that record one changed it.
func TestReadSessions_RecordsTheLatestPermissionMode(t *testing.T) {
	m := readOne(t,
		`{"type":"permission-mode","permissionMode":"default"}`,
		`{"type":"user","permissionMode":"acceptEdits","message":{"role":"user","content":"hi"}}`,
		`{"type":"permission-mode","permissionMode":"plan"}`)
	if m.PermissionMode != "plan" {
		t.Errorf("PermissionMode = %q, want the last, plan", m.PermissionMode)
	}
}

func TestReadSessions_AnUnusablePermissionModeNeverClobbersAGoodOne(t *testing.T) {
	m := readOne(t,
		`{"type":"permission-mode","permissionMode":"acceptEdits"}`,
		`{"type":"permission-mode","permissionMode":"has space!"}`,
		`{"type":"permission-mode","permissionMode":""}`,
		`{"type":"permission-mode","permissionMode":"`+strings.Repeat("x", 40)+`"}`,
		`{"type":"permission-mode","permissionMode":"a\u001b[0m"}`)
	if m.PermissionMode != "acceptEdits" {
		t.Errorf("PermissionMode = %q, want acceptEdits", m.PermissionMode)
	}
}

func TestReadSessions_NoCwdAndNoModeLeavesBothEmpty(t *testing.T) {
	m := readOne(t, `{"type":"ai-title","aiTitle":"just a title"}`)
	if m.Cwd != "" || m.PermissionMode != "" {
		t.Errorf("Cwd %q mode %q, want both empty: a harvester must not invent a value", m.Cwd, m.PermissionMode)
	}
}

func TestSessionMetadata_NewFieldsAreOmittedWhenEmpty(t *testing.T) {
	b, err := json.Marshal(SessionMetadata{Title: "x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"cwd"`, `"permissionMode"`, `"rev"`} {
		if strings.Contains(string(b), k) {
			t.Errorf("%s written for an entry that has none: %s", k, b)
		}
	}
}

// An entry written before these fields existed cannot vouch for its transcript, so an
// incremental harvest re-reads it ONCE and it gains them. Without this the skip, which keys on
// mtime alone, would leave every old entry without a cwd until its transcript next changed.
func TestHarvest_AnEntryFromBeforeTheNewFieldsIsReReadOnce(t *testing.T) {
	metadataHome(t)
	cfg := filepath.Join(t.TempDir(), "claude")
	proj := filepath.Join(cfg, "projects", "-p")
	writeSessionTranscript(t, proj, "s1.jsonl",
		`{"type":"ai-title","aiTitle":"t"}`, `{"type":"system","cwd":"/w/start"}`)
	touch(t, filepath.Join(proj, "s1.jsonl"), time.Now().Add(-time.Hour))

	first, err := Harvest(Options{ConfigDir: cfg, Merge: true})
	if err != nil {
		t.Fatal(err)
	}
	meta := readMetadataFile(t, first.Path)
	if meta["s1"].Cwd != "/w/start" || meta["s1"].HarvestRev != CurrentHarvestRev {
		t.Fatalf("first harvest = %+v, want the cwd and the current revision", meta["s1"])
	}

	// Now the same entry as an older release wrote it: no cwd, no revision.
	old := meta["s1"]
	old.Cwd, old.PermissionMode, old.HarvestRev = "", "", 0
	if err := SaveMetadata(first.Path, map[string]SessionMetadata{"s1": old}); err != nil {
		t.Fatal(err)
	}
	second, err := Harvest(Options{ConfigDir: cfg, Merge: true, Incremental: true})
	if err != nil {
		t.Fatal(err)
	}
	if second.Harvested != 1 || second.Skipped != 0 {
		t.Errorf("harvested/skipped = %d/%d, want 1/0: an old-revision entry must be re-read", second.Harvested, second.Skipped)
	}
	if got := readMetadataFile(t, second.Path)["s1"]; got.Cwd != "/w/start" {
		t.Errorf("Cwd after the re-read = %q, want /w/start", got.Cwd)
	}

	// And only once: the entry is now current, so the next incremental harvest skips it.
	third, err := Harvest(Options{ConfigDir: cfg, Merge: true, Incremental: true})
	if err != nil {
		t.Fatal(err)
	}
	if third.Skipped != 1 || third.Harvested != 0 {
		t.Errorf("harvested/skipped = %d/%d, want 0/1: the re-read must not repeat", third.Harvested, third.Skipped)
	}
	if got := readMetadataFile(t, third.Path)["s1"]; got.Cwd != "/w/start" {
		t.Errorf("a skipped session lost its Cwd: %+v", got)
	}
}
