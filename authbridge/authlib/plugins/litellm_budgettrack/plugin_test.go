package litellm_budgettrack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rossoctl/cortex/authbridge/authlib/pipeline"
)

// configure builds a BudgetTrack with a temp-dir spend file and the given budget.
func configure(t *testing.T, maxBudget float64) *BudgetTrack {
	t.Helper()
	p := New()
	cfg := budgetTrackConfig{
		SpendFile: filepath.Join(t.TempDir(), "spend.json"),
		MaxBudget: maxBudget,
	}
	raw, _ := json.Marshal(cfg)
	if err := p.Configure(raw); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	return p
}

// TestOnResponseReadsResponseHeader is the regression guard for the core fix:
// the cost must be read from ResponseHeaders, not the request Headers.
func TestOnResponseReadsResponseHeader(t *testing.T) {
	p := configure(t, 5.00)
	pctx := &pipeline.Context{
		ResponseHeaders: http.Header{responseCostHeader: {"0.0025"}},
	}

	if action := p.OnResponse(context.Background(), pctx); action.Type != pipeline.Continue {
		t.Fatalf("OnResponse() = %v, want Continue", action.Type)
	}
	if p.ledger.TotalSpend != 0.0025 {
		t.Errorf("TotalSpend = %v, want 0.0025", p.ledger.TotalSpend)
	}
	if p.ledger.TotalCalls != 1 {
		t.Errorf("TotalCalls = %d, want 1", p.ledger.TotalCalls)
	}
}

// TestOnResponseIgnoresRequestHeader guards against the original bug: the cost
// header on the request side (pctx.Headers) must NOT be accumulated.
func TestOnResponseIgnoresRequestHeader(t *testing.T) {
	p := configure(t, 5.00)
	pctx := &pipeline.Context{
		Headers:         http.Header{responseCostHeader: {"0.0025"}}, // wrong place; must be ignored
		ResponseHeaders: http.Header{},
	}

	p.OnResponse(context.Background(), pctx)
	if p.ledger.TotalSpend != 0 {
		t.Errorf("TotalSpend = %v, want 0 (request-header cost must be ignored)", p.ledger.TotalSpend)
	}
}

// TestOnResponseFallsBackToOriginal covers the Anthropic /v1/messages case where
// only the pre-discount "-original" header is present.
func TestOnResponseFallsBackToOriginal(t *testing.T) {
	p := configure(t, 5.00)
	pctx := &pipeline.Context{
		ResponseHeaders: http.Header{responseCostOriginalHeader: {"2.204e-05"}},
	}

	p.OnResponse(context.Background(), pctx)
	if p.ledger.TotalSpend != 2.204e-05 {
		t.Errorf("TotalSpend = %v, want 2.204e-05 (fallback header)", p.ledger.TotalSpend)
	}
}

// TestOnResponseBareHeaderWins verifies the effective (post-discount) header
// takes precedence over "-original" when both are present.
func TestOnResponseBareHeaderWins(t *testing.T) {
	p := configure(t, 5.00)
	pctx := &pipeline.Context{
		ResponseHeaders: http.Header{
			responseCostHeader:         {"0.001"},
			responseCostOriginalHeader: {"0.002"},
		},
	}

	p.OnResponse(context.Background(), pctx)
	if p.ledger.TotalSpend != 0.001 {
		t.Errorf("TotalSpend = %v, want 0.001 (bare header must win)", p.ledger.TotalSpend)
	}
}

// TestOnResponseIgnoresMissingOrInvalid verifies absent / non-positive / unparseable
// costs are skipped rather than corrupting the ledger.
func TestOnResponseIgnoresMissingOrInvalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
	}{
		{"missing", http.Header{}},
		{"zero", http.Header{responseCostHeader: {"0"}}},
		{"negative", http.Header{responseCostHeader: {"-1"}}},
		{"unparseable", http.Header{responseCostHeader: {"abc"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := configure(t, 5.00)
			pctx := &pipeline.Context{ResponseHeaders: tc.headers}
			if action := p.OnResponse(context.Background(), pctx); action.Type != pipeline.Continue {
				t.Fatalf("OnResponse() = %v, want Continue", action.Type)
			}
			if p.ledger.TotalSpend != 0 || p.ledger.TotalCalls != 0 {
				t.Errorf("ledger mutated: spend=%v calls=%d, want 0/0", p.ledger.TotalSpend, p.ledger.TotalCalls)
			}
		})
	}
}

// TestOnRequestEnforcesBudget verifies OnRequest denies with 429 once the
// accumulated spend reaches the daily budget, and allows before that.
func TestOnRequestEnforcesBudget(t *testing.T) {
	p := configure(t, 0.001)

	// Under budget: allowed.
	if action := p.OnRequest(context.Background(), &pipeline.Context{}); action.Type != pipeline.Continue {
		t.Fatalf("OnRequest() under budget = %v, want Continue", action.Type)
	}

	// Accumulate past the budget via a response.
	p.OnResponse(context.Background(), &pipeline.Context{
		ResponseHeaders: http.Header{responseCostHeader: {"0.002"}},
	})

	// Over budget: rejected with 429 / budget.exceeded.
	action := p.OnRequest(context.Background(), &pipeline.Context{})
	if action.Type != pipeline.Reject {
		t.Fatalf("OnRequest() over budget = %v, want Reject", action.Type)
	}
	if action.Violation == nil || action.Violation.Status != http.StatusTooManyRequests {
		t.Errorf("Violation = %+v, want Status 429", action.Violation)
	}
	if action.Violation.Code != "budget.exceeded" {
		t.Errorf("Violation.Code = %q, want budget.exceeded", action.Violation.Code)
	}
}

// TestLedgerPersistsAcrossInstances verifies the spend file is reloaded, so a
// restart on the same day resumes the accumulated total.
func TestLedgerPersistsAcrossInstances(t *testing.T) {
	spendFile := filepath.Join(t.TempDir(), "spend.json")
	raw, _ := json.Marshal(budgetTrackConfig{SpendFile: spendFile, MaxBudget: 5.00})

	p1 := New()
	if err := p1.Configure(raw); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	p1.OnResponse(context.Background(), &pipeline.Context{
		ResponseHeaders: http.Header{responseCostHeader: {"0.01"}},
	})

	p2 := New()
	if err := p2.Configure(raw); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if p2.ledger.TotalSpend != 0.01 {
		t.Errorf("reloaded TotalSpend = %v, want 0.01", p2.ledger.TotalSpend)
	}
}

// TestConfigureRejectsBadConfig verifies required-field and JSON validation.
func TestConfigureRejectsBadConfig(t *testing.T) {
	spend := filepath.Join(t.TempDir(), "spend.json")
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"empty spend_file", `{"max_budget": 5.0}`},
		{"zero max_budget", fmt.Sprintf(`{"spend_file": %q, "max_budget": 0}`, spend)},
		{"negative max_budget", fmt.Sprintf(`{"spend_file": %q, "max_budget": -1}`, spend)},
		{"invalid json", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := New().Configure(json.RawMessage(tc.raw)); err == nil {
				t.Errorf("Configure(%s) = nil, want error", tc.raw)
			}
		})
	}
}

// TestLoadLedgerResetsStaleDay verifies a spend file left over from a previous
// day is discarded on Configure rather than counted against today's budget.
func TestLoadLedgerResetsStaleDay(t *testing.T) {
	spend := filepath.Join(t.TempDir(), "spend.json")
	stale := `{"date":"2000-01-01","total_spend":9.99,"total_calls":42}`
	if err := os.WriteFile(spend, []byte(stale), 0o644); err != nil {
		t.Fatalf("seed spend file: %v", err)
	}

	p := New()
	raw, _ := json.Marshal(budgetTrackConfig{SpendFile: spend, MaxBudget: 5.00})
	if err := p.Configure(raw); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}

	today := time.Now().UTC().Format("2006-01-02")
	if p.ledger.Date != today {
		t.Errorf("ledger.Date = %q, want %q", p.ledger.Date, today)
	}
	if p.ledger.TotalSpend != 0 || p.ledger.TotalCalls != 0 {
		t.Errorf("stale ledger not reset: spend=%v calls=%d", p.ledger.TotalSpend, p.ledger.TotalCalls)
	}

	// A same-day ledger, by contrast, is preserved.
	sameDay := fmt.Sprintf(`{"date":%q,"total_spend":1.25,"total_calls":3}`, today)
	if err := os.WriteFile(spend, []byte(sameDay), 0o644); err != nil {
		t.Fatalf("seed same-day file: %v", err)
	}
	p2 := New()
	if err := p2.Configure(raw); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if p2.ledger.TotalSpend != 1.25 || p2.ledger.TotalCalls != 3 {
		t.Errorf("same-day ledger not preserved: spend=%v calls=%d", p2.ledger.TotalSpend, p2.ledger.TotalCalls)
	}
}

// TestConcurrentOnResponse exercises the mutex under concurrent responses.
// Run with -race to catch data races on the ledger.
func TestConcurrentOnResponse(t *testing.T) {
	p := configure(t, 1000.0) // high budget so nothing is rejected
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			p.OnResponse(context.Background(), &pipeline.Context{
				ResponseHeaders: http.Header{responseCostHeader: {"0.01"}},
			})
		}()
	}
	wg.Wait()

	if p.ledger.TotalCalls != goroutines {
		t.Errorf("TotalCalls = %d, want %d", p.ledger.TotalCalls, goroutines)
	}
	// 50 × 0.01 = 0.50, within float tolerance.
	if got := p.ledger.TotalSpend; got < 0.4999 || got > 0.5001 {
		t.Errorf("TotalSpend = %v, want ~0.50", got)
	}
}
