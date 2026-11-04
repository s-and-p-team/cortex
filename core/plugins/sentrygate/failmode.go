package sentrygate

import (
	"fmt"
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

// failRow is what applies to one request: the hold, the fallback, and the destination
// of the row that set them, "" for the defaults.
type failRow struct {
	destination string
	waitMS      int
	fallback    string
}

// foldHost is a host name as fail_mode compares it: case folded, and the trailing dot of
// a fully qualified name dropped, since both spellings dial the same host.
func foldHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }

// rowHost is a request host as fail_mode compares it: port stripped, then foldHost.
func rowHost(host string) string { return foldHost(hostOnly(host)) }

// decodeFailMode checks the rows and returns them by destination, each with the
// defaults filled in where it leaves a key out.
func decodeFailMode(rows []FailModeRow, waitMS int, fallback string) (map[string]failRow, error) {
	byHost := make(map[string]failRow, len(rows))
	for i, raw := range rows {
		d := foldHost(raw.Destination)
		// A port, a scheme, a space or a wildcard is never on the host the gate compares,
		// so such a row could never match.
		if d == "" || strings.ContainsAny(d, ":/ \t*?[") {
			return nil, fmt.Errorf("sentry-gate config: fail_mode row %d: destination %q must be one host name, with no port, no scheme and no wildcard", i, raw.Destination)
		}
		if _, dup := byHost[d]; dup {
			return nil, fmt.Errorf("sentry-gate config: fail_mode row %d: destination %q is given twice", i, raw.Destination)
		}
		if raw.WaitMS == nil && raw.Fallback == nil {
			return nil, fmt.Errorf("sentry-gate config: fail_mode row %d (%s) sets neither wait_ms nor fallback", i, d)
		}
		r := failRow{destination: d, waitMS: waitMS, fallback: fallback}
		if raw.WaitMS != nil {
			if r.waitMS = *raw.WaitMS; r.waitMS < 1 || r.waitMS > maxWaitMS {
				return nil, fmt.Errorf("sentry-gate config: fail_mode row %d (%s): wait_ms %d must be 1..%d", i, d, r.waitMS, maxWaitMS)
			}
		}
		if raw.Fallback != nil {
			if r.fallback = *raw.Fallback; r.fallback != "deny" && r.fallback != "allow" {
				return nil, fmt.Errorf("sentry-gate config: fail_mode row %d (%s): fallback %q must be deny or allow", i, d, r.fallback)
			}
		}
		byHost[d] = r
	}
	return byHost, nil
}

// failRowFor is the row for a request's host, or the defaults.
func (g *Gate) failRowFor(host string) failRow {
	if r, ok := g.cfg.rows[rowHost(host)]; ok {
		return r
	}
	return failRow{waitMS: g.cfg.WaitMS, fallback: g.cfg.Fallback}
}
