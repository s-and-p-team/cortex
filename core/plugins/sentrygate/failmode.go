package sentrygate

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// FailModeRow is one row of fail_mode: for requests to one destination host, a hold
// (wait_ms) and a fallback that replace the defaults of the same names. A key the row
// leaves out keeps the default.
type FailModeRow struct {
	Destination string  `json:"destination"`
	WaitMS      *int    `json:"wait_ms,omitempty"`
	Fallback    *string `json:"fallback,omitempty"`
}

// Slice is the fail mode of one source workload, under sources: its own defaults and
// rows. A default it leaves out is the top-level key, a row's missing key its default.
type Slice struct {
	WaitMS   *int          `json:"wait_ms,omitempty"`
	Fallback *string       `json:"fallback,omitempty"`
	FailMode []FailModeRow `json:"fail_mode,omitempty"`
}

// failRow is what applies to one request: the hold, the fallback, and the destination
// of the row and the source of the slice that set them, "" for the top level.
type failRow struct {
	destination string
	source      string
	waitMS      int
	fallback    string
}

// failSlice is a decoded slice: its defaults and its rows by destination.
type failSlice struct {
	defaults failRow
	rows     map[string]failRow
}

// foldHost is a host name as fail_mode compares it: case folded, and the trailing dot of
// a fully qualified name dropped, since both spellings dial the same host.
func foldHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }

// rowHost is a request host as fail_mode compares it: port stripped, then foldHost.
func rowHost(host string) string { return foldHost(hostOnly(host)) }

// withKeys is r with the keys given set over it, each checked.
func withKeys(r failRow, waitMS *int, fallback *string) (failRow, error) {
	if waitMS != nil {
		if r.waitMS = *waitMS; r.waitMS < 1 || r.waitMS > maxWaitMS {
			return r, fmt.Errorf("wait_ms %d must be 1..%d", r.waitMS, maxWaitMS)
		}
	}
	if fallback != nil {
		if r.fallback = *fallback; r.fallback != "deny" && r.fallback != "allow" {
			return r, fmt.Errorf("fallback %q must be deny or allow", r.fallback)
		}
	}
	return r, nil
}

// decodeFailMode checks the rows found at where and returns them by destination, each
// with def filled in where it leaves a key out.
func decodeFailMode(where string, rows []FailModeRow, def failRow) (map[string]failRow, error) {
	byHost := make(map[string]failRow, len(rows))
	for i, raw := range rows {
		d := foldHost(raw.Destination)
		// A port, a scheme, a space or a wildcard is never on the host the gate compares,
		// so such a row could never match.
		if d == "" || strings.ContainsAny(d, ":/ \t*?[") {
			return nil, fmt.Errorf("sentry-gate config: %s row %d: destination %q must be one host name, with no port, no scheme and no wildcard", where, i, raw.Destination)
		}
		if _, dup := byHost[d]; dup {
			return nil, fmt.Errorf("sentry-gate config: %s row %d: destination %q is given twice", where, i, raw.Destination)
		}
		if raw.WaitMS == nil && raw.Fallback == nil {
			return nil, fmt.Errorf("sentry-gate config: %s row %d (%s) sets neither wait_ms nor fallback", where, i, d)
		}
		def.destination = d
		r, err := withKeys(def, raw.WaitMS, raw.Fallback)
		if err != nil {
			return nil, fmt.Errorf("sentry-gate config: %s row %d (%s): %w", where, i, d, err)
		}
		byHost[d] = r
	}
	return byHost, nil
}

// decodeSlices decodes fail_mode into the unnamed slice, with the top-level defaults,
// and sources into a slice per source, the top level filled in where one leaves a
// default out.
func decodeSlices(cfg *Config) (err error) {
	cfg.unnamed.defaults = failRow{waitMS: cfg.WaitMS, fallback: cfg.Fallback}
	if cfg.unnamed.rows, err = decodeFailMode("fail_mode", cfg.FailMode, cfg.unnamed.defaults); err != nil {
		return err
	}
	cfg.sources = make(map[string]failSlice, len(cfg.Sources))
	for _, name := range slices.Sorted(maps.Keys(cfg.Sources)) {
		// self_id is one segment of a SPIFFE ID, so a name that is empty or holds a /
		// could never be a request's source.
		if name == "" || strings.Contains(name, "/") {
			return fmt.Errorf("sentry-gate config: sources[%q]: a source name must be one non-empty segment, with no /", name)
		}
		s, sl := cfg.Sources[name], failSlice{defaults: cfg.unnamed.defaults}
		sl.defaults.source = name
		if sl.defaults, err = withKeys(sl.defaults, s.WaitMS, s.Fallback); err != nil {
			return fmt.Errorf("sentry-gate config: sources[%q]: %w", name, err)
		}
		if sl.rows, err = decodeFailMode(fmt.Sprintf("sources[%q].fail_mode", name), s.FailMode, sl.defaults); err != nil {
			return err
		}
		cfg.sources[name] = sl
	}
	return nil
}

// failRowFor is the row for a request from source to host: source's slice, else the
// unnamed one; in it, host's row, else the slice's defaults.
func (g *Gate) failRowFor(source, host string) failRow {
	s, ok := g.cfg.sources[source]
	if !ok {
		s = g.cfg.unnamed
	}
	if r, ok := s.rows[rowHost(host)]; ok {
		return r
	}
	return s.defaults
}
