// Package spiffe provides credential sources for SPIFFE-based authentication.
package spiffe

import "context"

// JWTSource provides JWT tokens for client authentication during token exchange.
type JWTSource interface {
	// FetchToken returns a JWT token string for use as a client assertion.
	// Implementations may re-read from disk or fetch from the SPIFFE Workload API.
	FetchToken(ctx context.Context) (string, error)
}
