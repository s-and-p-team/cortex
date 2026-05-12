package cache

import (
	"testing"
	"time"
)

func TestGetSet(t *testing.T) {
	c := New()
	c.Set("token-abc", "aud-1", "exchanged-xyz", 5*time.Minute)

	got, ok := c.Get("token-abc", "aud-1")
	if !ok || got != "exchanged-xyz" {
		t.Errorf("Get() = (%q, %v), want (%q, true)", got, ok, "exchanged-xyz")
	}
}

func TestGetMiss(t *testing.T) {
	c := New()
	_, ok := c.Get("nonexistent", "aud")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestGetDifferentAudience(t *testing.T) {
	c := New()
	c.Set("token-abc", "aud-1", "exchanged-1", 5*time.Minute)

	_, ok := c.Get("token-abc", "aud-2")
	if ok {
		t.Error("expected cache miss for different audience")
	}
}

func TestTTLTooShort(t *testing.T) {
	c := New()
	c.Set("token", "aud", "val", 20*time.Second) // below 30s threshold
	if c.Len() != 0 {
		t.Error("expected no entry for TTL below threshold")
	}
}

func TestMaxSize(t *testing.T) {
	c := New(WithMaxSize(2))
	c.Set("t1", "a", "v1", 5*time.Minute)
	c.Set("t2", "a", "v2", 5*time.Minute)
	c.Set("t3", "a", "v3", 5*time.Minute) // should trigger eviction

	if c.Len() > 2 {
		t.Errorf("cache has %d entries, want <= 2", c.Len())
	}
}

func TestCacheKeyCollisionResistance(t *testing.T) {
	// Keys must differ when tokens or audiences differ
	k1 := cacheKey("abc", "def")
	k2 := cacheKey("ab", "cdef")
	k3 := cacheKey("abc", "de")
	if k1 == k2 {
		t.Error("different token/audience combos produced same key")
	}
	if k1 == k3 {
		t.Error("different audience produced same key")
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New()
	done := make(chan struct{})
	for i := range 100 {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			token := string(rune('A' + n%26))
			c.Set(token, "aud", "val", 5*time.Minute)
			c.Get(token, "aud")
		}(i)
	}
	for range 100 {
		<-done
	}
}
