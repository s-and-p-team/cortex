package spiffe

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// FileJWTSource reads a JWT-SVID from a file on every call.
// This supports spiffe-helper's rotation pattern (~2.5 min rotation)
// by always reading the latest token from disk.
type FileJWTSource struct {
	path string
}

// NewFileJWTSource creates a JWTSource that reads from the given file path.
func NewFileJWTSource(path string) *FileJWTSource {
	return &FileJWTSource{path: path}
}

// FetchToken reads and returns the JWT-SVID from the configured file.
func (s *FileJWTSource) FetchToken(_ context.Context) (string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return "", fmt.Errorf("reading JWT-SVID from %s: %w", s.path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("JWT-SVID file %s is empty", s.path)
	}
	return token, nil
}
