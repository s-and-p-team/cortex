package access

import (
	"net/url"
	"strings"
)

// WebFetch(domain:host) rules (permissions, "WebFetch"): they match the HOSTNAME of the
// requested URL, case-insensitively, with one trailing dot stripped from both sides.
//
//   - domain:example.com matches example.com only;
//   - domain:*.example.com matches any subdomain at any depth, but not example.com itself;
//   - domain:* matches every domain;
//   - elsewhere a * matches only the text between two dots, so example.* matches example.org
//     and not example.evil.com: a trailing wildcard must not reach domains an attacker can
//     register.

// fetchHost returns the lower-cased hostname of the URL a WebFetch call requests, without
// brackets, port or a trailing dot. The standard library parses the URL: a hand-rolled split
// is where "https://good.com@evil.net/" turns into a fetch of good.com.
func fetchHost(c Call) (string, bool) {
	raw, ok := c.Input["url"].(string)
	if !ok || raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	h := strings.ToLower(u.Hostname())
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", false
	}
	return h, true
}

// domainMatches applies one domain pattern to a host. Both are already lower-cased, and the
// pattern has any trailing dot removed.
func domainMatches(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*."):
		// any subdomain at any depth, never the apex
		// The suffix keeps its leading dot, so the apex (example.com) cannot end with it: no
		// separate length check is needed to exclude it. A second * in the suffix (*.*.com) is a
		// shape the docs do not describe; the suffix then contains a literal *, which no
		// hostname does, so it never matches.
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix)
	case !strings.Contains(pattern, "*"):
		return pattern == host
	}
	// A * elsewhere matches exactly one label's worth of text: it cannot cross a dot.
	return labelGlob(pattern, host)
}

// labelGlob matches host against pattern label by label, so a * stays inside its label.
func labelGlob(pattern, host string) bool {
	pl, hl := strings.Split(pattern, "."), strings.Split(host, ".")
	if len(pl) != len(hl) {
		return false
	}
	for i := range pl {
		if !segGlob(pl[i], hl[i]) {
			return false
		}
	}
	return true
}

// evaluateWebFetch evaluates a WebFetch rule that has a specifier.
func evaluateWebFetch(r Rule, pattern string, c Call, res evalResult) evalResult {
	domain, isDomain := strings.CutPrefix(strings.TrimSpace(pattern), "domain:")
	if !isDomain {
		// A WebFetch specifier that is not domain: is not one this view understands.
		res.state = evalUnknown
		res.caveats = append(res.caveats, r.Raw+": only WebFetch(domain:...) rules are evaluated")
		return res
	}
	domain = strings.TrimSpace(domain)
	host, ok := fetchHost(c)
	if !ok {
		if r.Decision == Allow {
			return res
		}
		res.state = evalUnknown
		res.caveats = append(res.caveats, r.Raw+": the call's URL has no host that can be read")
		return res
	}
	if domainMatches(domain, host) {
		res.state = evalMatch
	}
	return res
}
