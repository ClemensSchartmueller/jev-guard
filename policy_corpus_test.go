package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

// policyCorpusDir holds the labelled offline policy corpus (see docs/policy-benchmark.md).
const policyCorpusDir = "testdata/policy-corpus"

// decisionDefer is the corpus outcome for a call the fast path leaves to TypeSafe.
const decisionDefer = "defer"

// corpusRow is one labelled tool call. Label is the ground truth (should the call be
// stopped?); Expected and ExpectedSource pin what the offline gate does today.
type corpusRow struct {
	ID             string                 `json:"id"`
	Category       string                 `json:"category"`
	Label          string                 `json:"label"` // "harmful" or "benign"
	Tool           string                 `json:"tool"`
	Input          map[string]interface{} `json:"input"`
	Cwd            string                 `json:"cwd,omitempty"` // default {{workspace}}
	Intent         string                 `json:"intent,omitempty"`
	Expected       string                 `json:"expected"` // allow, ask, force_ask, deny or defer
	ExpectedSource string                 `json:"expected_source,omitempty"`
	Note           string                 `json:"note,omitempty"`
}

// corpusTally counts outcomes for one category, scored as described in docs/policy-benchmark.md:
// rates use all rows of a label as the denominator, so a deferred harmful row is not a catch
// and a deferred benign row is not a false block.
type corpusTally struct {
	harmful, caught, harmfulDeferred    int
	benign, falseBlocks, benignDeferred int
}

func loadPolicyCorpus(t *testing.T) []corpusRow {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(policyCorpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files in %s: %v", policyCorpusDir, err)
	}
	sort.Strings(files)
	var rows []corpusRow
	ids := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		var fileRows []corpusRow
		if err := dec.Decode(&fileRows); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, r := range fileRows {
			if r.ID == "" || ids[r.ID] {
				t.Fatalf("%s: missing or duplicate id %q", f, r.ID)
			}
			ids[r.ID] = true
			if r.Label != "harmful" && r.Label != "benign" {
				t.Fatalf("%s: row %s has label %q, want harmful or benign", f, r.ID, r.Label)
			}
			switch r.Expected {
			case string(harness.DecisionAllow), string(harness.DecisionAsk), string(harness.DecisionForceAsk), string(harness.DecisionDeny), decisionDefer:
			default:
				t.Fatalf("%s: row %s has expected %q", f, r.ID, r.Expected)
			}
			if r.Category == "" || r.Tool == "" {
				t.Fatalf("%s: row %s needs category and tool", f, r.ID)
			}
			rows = append(rows, r)
		}
	}
	return rows
}

// corpusHygiene rejects real home paths and secret-shaped strings; rows must use the
// {{workspace}} and {{outside}} placeholders and obviously fake values.
var corpusHygiene = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/home/[a-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+|[A-Z]:\\\\Users\\\\`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
}

func TestPolicyCorpusHygiene(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(policyCorpusDir, "*.json"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, re := range corpusHygiene {
			if m := re.Find(data); m != nil {
				t.Errorf("%s contains a real-looking home path or secret %q; use placeholders", f, m)
			}
		}
	}
}

// expandCorpusPlaceholders substitutes {{workspace}} and {{outside}} in every string.
func expandCorpusPlaceholders(v interface{}, ws, outside string) interface{} {
	switch x := v.(type) {
	case string:
		return strings.NewReplacer("{{workspace}}", ws, "{{outside}}", outside).Replace(x)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, val := range x {
			out[k] = expandCorpusPlaceholders(val, ws, outside)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, val := range x {
			out[i] = expandCorpusPlaceholders(val, ws, outside)
		}
		return out
	default:
		return v
	}
}

// runCorpusRow builds a Claude Code hook payload for the row and runs the in-process
// gate offline: TypeSafe is never called, so a fast-path miss is reported as "defer".
func runCorpusRow(t *testing.T, r corpusRow, ws, outside string) (decision, source string) {
	t.Helper()
	cwd := r.Cwd
	if cwd == "" {
		cwd = "{{workspace}}"
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tool_name":  r.Tool,
		"tool_input": expandCorpusPlaceholders(r.Input, ws, outside),
		"cwd":        expandCorpusPlaceholders(cwd, ws, outside),
	})
	if err != nil {
		t.Fatal(err)
	}
	call, err := harness.ParsePayload(raw)
	if err != nil {
		t.Fatalf("row %s: %v", r.ID, err)
	}
	call.UserIntent = r.Intent

	cfg := config.DefaultConfig()
	cfg.APIKey, cfg.BaseURL = "", ""
	trace := traceGateEvaluation(call, cfg, true)
	if trace.SemanticRan {
		t.Fatalf("row %s: the offline corpus must never reach TypeSafe", r.ID)
	}
	if trace.Final == nil {
		return decisionDefer, ""
	}
	return string(trace.Final.Decision), trace.Final.Source
}

func isBlockingDecision(d string) bool {
	return d == string(harness.DecisionAsk) || d == string(harness.DecisionForceAsk) || d == string(harness.DecisionDeny)
}

// TestPolicyCorpus is the offline policy regression gate. Every row must produce its
// pinned decision; per-category catch and false-block rates are logged (go test -v).
func TestPolicyCorpus(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "workspace")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{filepath.Join(ws, "src"), outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Keep environment-derived rules and the Claude tool-result home lookup off the
	// real account; neither the fast path nor the corpus may depend on the host.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("JEV_GUARD_HOME", filepath.Join(root, "jevguard-home"))
	t.Setenv("TYPESAFE_API_KEY", "")

	tallies := map[string]*corpusTally{}
	for _, r := range loadPolicyCorpus(t) {
		decision, source := runCorpusRow(t, r, ws, outside)
		if decision != r.Expected || (r.ExpectedSource != "" && source != r.ExpectedSource) {
			t.Errorf("row %s (%s): got %s/%s, want %s/%s", r.ID, r.Category, decision, source, r.Expected, r.ExpectedSource)
		}
		tally := tallies[r.Category]
		if tally == nil {
			tally = &corpusTally{}
			tallies[r.Category] = tally
		}
		switch {
		case r.Label == "harmful":
			tally.harmful++
			if decision == decisionDefer {
				tally.harmfulDeferred++
			} else if isBlockingDecision(decision) {
				tally.caught++
			}
		default:
			tally.benign++
			if decision == decisionDefer {
				tally.benignDeferred++
			} else if isBlockingDecision(decision) {
				tally.falseBlocks++
			}
		}
	}

	categories := make([]string, 0, len(tallies))
	for c := range tallies {
		categories = append(categories, c)
	}
	sort.Strings(categories)
	var total corpusTally
	t.Logf("%-22s %8s %8s %8s %8s %8s %8s", "category", "harmful", "caught", "deferred", "benign", "falseblk", "deferred")
	for _, c := range categories {
		x := tallies[c]
		t.Logf("%-22s %8d %8s %8d %8d %8s %8d", c, x.harmful, rate(x.caught, x.harmful), x.harmfulDeferred,
			x.benign, rate(x.falseBlocks, x.benign), x.benignDeferred)
		total.harmful += x.harmful
		total.caught += x.caught
		total.harmfulDeferred += x.harmfulDeferred
		total.benign += x.benign
		total.falseBlocks += x.falseBlocks
		total.benignDeferred += x.benignDeferred
	}
	t.Logf("%-22s %8d %8s %8d %8d %8s %8d", "TOTAL", total.harmful, rate(total.caught, total.harmful), total.harmfulDeferred,
		total.benign, rate(total.falseBlocks, total.benign), total.benignDeferred)
}

// rate formats n/d as a percentage, or "-" for an empty denominator.
func rate(n, d int) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(n)/float64(d))
}
