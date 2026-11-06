package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitRoot_FindsTheNearestDotGitAndNothingOutsideARepo(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := GitRoot(sub); got != "" {
		t.Errorf("GitRoot outside a repository = %q, want empty", got)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := GitRoot(sub); got != root {
		t.Errorf("GitRoot = %q, want %q", got, root)
	}
	// A worktree's .git is a file, not a directory; it still marks the root.
	inner := filepath.Join(root, "a")
	if err := os.WriteFile(filepath.Join(inner, ".git"), []byte("gitdir: x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := GitRoot(sub); got != inner {
		t.Errorf("GitRoot with a .git file = %q, want the nearer %q", got, inner)
	}
}

func TestLocalInput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	proj := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("explicit cwd is absolute and carries the home", func(t *testing.T) {
		in, err := LocalInput(proj, "", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if in.Cwd != proj || in.Home != home || in.FS == nil || in.GOOS == "" {
			t.Errorf("Input = %+v", in)
		}
	})
	t.Run("relative cwd is resolved against the working directory", func(t *testing.T) {
		t.Chdir(filepath.Dir(proj))
		in, err := LocalInput("proj", "", "", false)
		if err != nil || in.Cwd != proj {
			t.Errorf("Cwd = %q err %v, want %q", in.Cwd, err, proj)
		}
	})
	t.Run("empty cwd means the current directory", func(t *testing.T) {
		t.Chdir(proj)
		in, err := LocalInput("", "", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := filepath.EvalSymlinks(in.Cwd); got != mustEval(t, proj) {
			t.Errorf("Cwd = %q, want the current directory %q", in.Cwd, proj)
		}
	})
	t.Run("empty cwd stays empty when it is known to be unknown", func(t *testing.T) {
		t.Chdir(proj)
		in, err := LocalInput("", "", "", true)
		if err != nil || in.Cwd != "" || in.GitRoot != "" {
			t.Errorf("Cwd %q GitRoot %q err %v, want both empty: falling back to the current directory would show an unrelated project's policy", in.Cwd, in.GitRoot, err)
		}
	})
	t.Run("config dir falls back to the environment, an explicit one wins", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "envclaude")
		t.Setenv("CLAUDE_CONFIG_DIR", env)
		if in, _ := LocalInput(proj, "", "", false); in.ConfigDir != env {
			t.Errorf("ConfigDir = %q, want the environment's %q", in.ConfigDir, env)
		}
		explicit := filepath.Join(t.TempDir(), "explicit")
		if in, _ := LocalInput(proj, explicit, "", false); in.ConfigDir != explicit {
			t.Errorf("ConfigDir = %q, want the explicit %q", in.ConfigDir, explicit)
		}
	})
	t.Run("the git root is found for a subdirectory", func(t *testing.T) {
		repo := t.TempDir()
		sub := filepath.Join(repo, "x", "y")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		in, _ := LocalInput(sub, "", "", false)
		if in.GitRoot != repo {
			t.Errorf("GitRoot = %q, want %q", in.GitRoot, repo)
		}
	})
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDescribeSession(t *testing.T) {
	cases := []struct {
		id, title, cwd string
		want           []string
		notWant        []string
	}{
		{"abc", "fix it", "/w/p", []string{"session abc", "(fix it)", "started in /w/p"}, nil},
		{"abc", "", "/w/p", []string{"session abc", "started in /w/p"}, []string{"()"}},
		{"abc", "t", "", []string{"no working directory recorded", "not shown"}, []string{"started in"}},
		{"a\x07b", "t\x07", "/w\x1b[0m", []string{"session ab"}, []string{"\x1b", "\x07"}},
	}
	for _, c := range cases {
		got := DescribeSession(c.id, c.title, c.cwd)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("DescribeSession(%q,%q,%q) = %q, lacks %q", c.id, c.title, c.cwd, got, w)
			}
		}
		for _, w := range c.notWant {
			if strings.Contains(got, w) {
				t.Errorf("DescribeSession(%q,%q,%q) = %q, should not contain %q", c.id, c.title, c.cwd, got, w)
			}
		}
	}
}
