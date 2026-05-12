package spiffe

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileJWTSource_FetchToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt_svid.token")
	if err := os.WriteFile(path, []byte("eyJhbGciOiJSUzI1NiJ9.test.sig\n"), 0600); err != nil {
		t.Fatal(err)
	}

	src := NewFileJWTSource(path)
	token, err := src.FetchToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "eyJhbGciOiJSUzI1NiJ9.test.sig" {
		t.Errorf("got %q, want trimmed token", token)
	}
}

func TestFileJWTSource_FileNotFound(t *testing.T) {
	src := NewFileJWTSource("/nonexistent/path")
	_, err := src.FetchToken(context.Background())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFileJWTSource_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.token")
	if err := os.WriteFile(path, []byte("  \n"), 0600); err != nil {
		t.Fatal(err)
	}

	src := NewFileJWTSource(path)
	_, err := src.FetchToken(context.Background())
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestFileJWTSource_ReReadsOnEveryCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotating.token")
	if err := os.WriteFile(path, []byte("token-v1"), 0600); err != nil {
		t.Fatal(err)
	}

	src := NewFileJWTSource(path)
	ctx := context.Background()

	tok1, _ := src.FetchToken(ctx)
	if tok1 != "token-v1" {
		t.Fatalf("got %q, want token-v1", tok1)
	}

	// Simulate rotation
	if err := os.WriteFile(path, []byte("token-v2"), 0600); err != nil {
		t.Fatal(err)
	}

	tok2, _ := src.FetchToken(ctx)
	if tok2 != "token-v2" {
		t.Errorf("got %q, want token-v2 after rotation", tok2)
	}
}
