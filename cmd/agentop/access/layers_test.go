package access

import (
	"testing"
	"testing/fstest"
)

func kinds(ls []Layer) []LayerKind {
	out := make([]LayerKind, len(ls))
	for i, l := range ls {
		out[i] = l.Kind
	}
	return out
}

func TestDiscoverLayers_OrderAndPresence(t *testing.T) {
	fsys := fstest.MapFS{
		"proj/.claude/settings.json": {Data: []byte(`{}`)},
		"home/.claude/settings.json": {Data: []byte(`{}`)},
	}
	in := Input{Cwd: "/proj", Home: "/home", FS: fsys, GOOS: "darwin"}
	got := discoverLayers(in)

	want := []LayerKind{Managed, CLI, Local, Project, User}
	gk := kinds(got)
	if len(gk) != len(want) {
		t.Fatalf("layers = %v, want %v", gk, want)
	}
	for i := range want {
		if gk[i] != want[i] {
			t.Fatalf("layers = %v, want %v", gk, want)
		}
	}
	by := map[LayerKind]Layer{}
	for _, l := range got {
		by[l.Kind] = l
	}
	if !by[Project].Present || by[Project].Path != "/proj/.claude/settings.json" {
		t.Errorf("project layer = %+v, want present at /proj/.claude/settings.json", by[Project])
	}
	if !by[User].Present || by[User].Path != "/home/.claude/settings.json" {
		t.Errorf("user layer = %+v, want present at /home/.claude/settings.json", by[User])
	}
	if by[Local].Present || by[Managed].Present || by[CLI].Present {
		t.Errorf("absent layers reported present: local=%v managed=%v cli=%v",
			by[Local].Present, by[Managed].Present, by[CLI].Present)
	}
}

func TestDiscoverLayers_ConfigDirOverridesHome(t *testing.T) {
	fsys := fstest.MapFS{"alt/settings.json": {Data: []byte(`{}`)}}
	in := Input{Cwd: "/proj", Home: "/home", ConfigDir: "/alt", FS: fsys, GOOS: "linux"}
	for _, l := range discoverLayers(in) {
		if l.Kind == User && (!l.Present || l.Path != "/alt/settings.json") {
			t.Errorf("user layer = %+v, want present at /alt/settings.json", l)
		}
	}
}

func TestDiscoverLayers_ManagedDropInsFollowBaseInAlphabeticalOrder(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/claude-code/managed-settings.json":           {Data: []byte(`{}`)},
		"etc/claude-code/managed-settings.d/20-b.json":    {Data: []byte(`{}`)},
		"etc/claude-code/managed-settings.d/10-a.json":    {Data: []byte(`{}`)},
		"etc/claude-code/managed-settings.d/.hidden.json": {Data: []byte(`{}`)},
		"etc/claude-code/managed-settings.d/notes.txt":    {Data: []byte(`x`)},
	}
	in := Input{Cwd: "/proj", Home: "/home", FS: fsys, GOOS: "linux"}
	var m Layer
	for _, l := range discoverLayers(in) {
		if l.Kind == Managed {
			m = l
		}
	}
	want := []string{
		"/etc/claude-code/managed-settings.json",
		"/etc/claude-code/managed-settings.d/10-a.json",
		"/etc/claude-code/managed-settings.d/20-b.json",
	}
	if len(m.Files) != len(want) {
		t.Fatalf("managed files = %v, want %v", m.Files, want)
	}
	for i, f := range m.Files {
		if f.Path != want[i] || !f.Present {
			t.Errorf("managed file %d = %+v, want present %s", i, f, want[i])
		}
	}
}

func TestDiscoverLayers_ManagedPathPerOS(t *testing.T) {
	cases := map[string]string{
		"darwin": "/Library/Application Support/ClaudeCode/managed-settings.json",
		"linux":  "/etc/claude-code/managed-settings.json",
	}
	for goos, want := range cases {
		in := Input{Cwd: "/p", Home: "/h", FS: fstest.MapFS{}, GOOS: goos}
		for _, l := range discoverLayers(in) {
			if l.Kind == Managed && l.Path != want {
				t.Errorf("%s managed path = %q, want %q", goos, l.Path, want)
			}
		}
	}
}

func TestDiscoverLayers_LocalFileLivesAtTheGitRootAndLegacyCwdIsAlsoRead(t *testing.T) {
	fsys := fstest.MapFS{
		"repo/.claude/settings.local.json":     {Data: []byte(`{}`)},
		"repo/sub/.claude/settings.local.json": {Data: []byte(`{}`)},
		"repo/sub/.claude/settings.json":       {Data: []byte(`{}`)},
	}
	in := Input{Cwd: "/repo/sub", GitRoot: "/repo", Home: "/h", FS: fsys, GOOS: "linux"}
	by := map[LayerKind]Layer{}
	for _, l := range discoverLayers(in) {
		by[l.Kind] = l
	}
	if by[Local].Path != "/repo/.claude/settings.local.json" {
		t.Errorf("local primary path = %q, want the git root's file", by[Local].Path)
	}
	if len(by[Local].Files) != 2 || !by[Local].Files[0].Present || !by[Local].Files[1].Present {
		t.Errorf("local files = %+v, want the root file and the legacy cwd file, both present", by[Local].Files)
	}
	// The shared file is read from the primary working directory only.
	if by[Project].Path != "/repo/sub/.claude/settings.json" {
		t.Errorf("project path = %q, want it under cwd, not the git root", by[Project].Path)
	}
}

func TestDiscoverLayers_LocalStaysWithCwdWhenTheGitRootIsHome(t *testing.T) {
	in := Input{Cwd: "/h/proj", GitRoot: "/h", Home: "/h", FS: fstest.MapFS{}, GOOS: "linux"}
	for _, l := range discoverLayers(in) {
		if l.Kind == Local && l.Path != "/h/proj/.claude/settings.local.json" {
			t.Errorf("local path = %q, want it beside cwd when the repo root is the home dir", l.Path)
		}
	}
}

func TestDiscoverLayers_NoCwdMeansNoProjectLayers(t *testing.T) {
	in := Input{Home: "/h", FS: fstest.MapFS{}, GOOS: "linux"}
	for _, l := range discoverLayers(in) {
		if (l.Kind == Local || l.Kind == Project) && l.Path != "" {
			t.Errorf("%v layer has path %q with no cwd", l.Kind, l.Path)
		}
	}
}
