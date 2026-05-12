package tui

import "testing"

// formatCount's previous implementation mishandled 3/6/9-digit negatives
// because it counted the leading '-' as a digit when computing the first
// triplet — e.g. formatCount(-100) produced "-,100". This table covers the
// previously-broken bands along with the paths that already worked.
func TestFormatCount(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{5, "5"},
		{100, "100"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
		{10000000, "10,000,000"},
		{-5, "-5"},
		{-100, "-100"},
		{-999, "-999"},
		{-1000, "-1,000"},
		{-12345, "-12,345"},
		{-123456, "-123,456"},
		{-1234567, "-1,234,567"},
	}
	for _, c := range cases {
		if got := formatCount(c.in); got != c.want {
			t.Errorf("formatCount(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
