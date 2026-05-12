package validation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// JWKSVerifier validates JWTs using a JWKS endpoint with auto-refreshing key cache.
type JWKSVerifier struct {
	jwksURL  string
	issuer   string
	cache    *jwk.Cache
}

// JWKSOption configures JWKSVerifier behavior.
type JWKSOption func(*jwksConfig)

type jwksConfig struct {
	refreshInterval time.Duration
}

// WithRefreshInterval sets the JWKS cache refresh interval.
func WithRefreshInterval(d time.Duration) JWKSOption {
	return func(c *jwksConfig) { c.refreshInterval = d }
}

// NewJWKSVerifier creates a Verifier that validates JWTs against a JWKS endpoint.
// The JWKS keys are cached and auto-refreshed in the background.
func NewJWKSVerifier(ctx context.Context, jwksURL, issuer string, opts ...JWKSOption) (*JWKSVerifier, error) {
	cfg := &jwksConfig{
		refreshInterval: 15 * time.Minute,
	}
	for _, o := range opts {
		o(cfg)
	}

	cache := jwk.NewCache(ctx)
	regOpts := []jwk.RegisterOption{
		jwk.WithMinRefreshInterval(cfg.refreshInterval),
	}
	if err := cache.Register(jwksURL, regOpts...); err != nil {
		return nil, fmt.Errorf("registering JWKS URL %s: %w", jwksURL, err)
	}

	return &JWKSVerifier{
		jwksURL: jwksURL,
		issuer:  issuer,
		cache:   cache,
	}, nil
}

// Verify parses and validates a JWT token against the cached JWKS.
// Checks signature, expiration, issuer, and audience.
func (v *JWKSVerifier) Verify(ctx context.Context, tokenStr string, audience string) (*Claims, error) {
	keySet, err := v.cache.Get(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	if audience == "" {
		return nil, fmt.Errorf("audience is required (prevents confused deputy attacks)")
	}

	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(audience),
	}

	token, err := jwt.Parse([]byte(tokenStr), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("validating JWT: %w", err)
	}

	claims := &Claims{
		Subject:   token.Subject(),
		Issuer:    token.Issuer(),
		Audience:  token.Audience(),
		ExpiresAt: token.Expiration(),
		Extra:     make(map[string]any),
	}

	// Extract "azp" (authorized party / client ID)
	if azp, ok := token.Get("azp"); ok {
		if s, ok := azp.(string); ok {
			claims.ClientID = s
		}
	}

	// Extract scopes from "scope" claim (space-separated string)
	if scopeVal, ok := token.Get("scope"); ok {
		if s, ok := scopeVal.(string); ok {
			claims.Scopes = strings.Fields(s)
		}
	}

	// Copy remaining private claims to Extra
	for k, v := range token.PrivateClaims() {
		if k != "azp" && k != "scope" {
			claims.Extra[k] = v
		}
	}

	return claims, nil
}
