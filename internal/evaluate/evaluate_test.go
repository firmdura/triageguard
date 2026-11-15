package evaluate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/firmdura/triageguard/internal/contracts"
	"github.com/firmdura/triageguard/internal/evaluate"
)

const digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type collectorFunc func(context.Context, contracts.Assumption) (contracts.Observation, error)

func (f collectorFunc) Observe(ctx context.Context, assumption contracts.Assumption) (contracts.Observation, error) {
	return f(ctx, assumption)
}

func str(value string) *string { return &value }

func config(value string) contracts.Observation {
	return contracts.Observation{State: contracts.ObservationPresent, Value: str(value)}
}

func hashed(digest string) contracts.Observation {
	return contracts.Observation{State: contracts.ObservationPresent, SHA256: str(digest)}
}

func absent() contracts.Observation {
	return contracts.Observation{State: contracts.ObservationAbsent}
}

func unavailable(reason contracts.ReasonCode) contracts.Observation {
	return contracts.Observation{State: contracts.ObservationUnavailable, Reason: reason}
}

func manifest(assumptions ...contracts.Assumption) contracts.Manifest {
	return contracts.Manifest{SchemaVersion: 1, Decisions: []contracts.Decision{{
		ID: "decision", CVE: "CVE-2024-0001", Baseline: "release-1", Rationale: "Synthetic human decision.",
		Assumptions: assumptions,
	}}}
}

func TestEvaluateComparisons(t *testing.T) {
	cases := []struct {
		name     string
		expect   contracts.Expectation
		observed contracts.Observation
		status   contracts.Status
		reason   contracts.ReasonCode
	}{
		{"config-match", &contracts.ConfigPresent{Key: "FEATURE", Value: "n"}, config("n"), contracts.StatusUnchanged, contracts.ReasonMatch},
		{"config-change", &contracts.ConfigPresent{Key: "FEATURE", Value: "n"}, config("y"), contracts.StatusReviewRequired, contracts.ReasonValueChanged},
		{"config-missing-key", &contracts.ConfigPresent{Key: "FEATURE", Value: "n"}, absent(), contracts.StatusReviewRequired, contracts.ReasonKeyMissing},
		{"config-empty-match", &contracts.ConfigPresent{Key: "FEATURE", Value: ""}, config(""), contracts.StatusUnchanged, contracts.ReasonMatch},
		{"config-empty-change", &contracts.ConfigPresent{Key: "FEATURE", Value: ""}, config("n"), contracts.StatusReviewRequired, contracts.ReasonValueChanged},
		{"config-empty-is-not-absent", &contracts.ConfigPresent{Key: "FEATURE", Value: ""}, absent(), contracts.StatusReviewRequired, contracts.ReasonKeyMissing},
		{"config-absence-match", &contracts.ConfigAbsent{Key: "FEATURE"}, absent(), contracts.StatusUnchanged, contracts.ReasonMatch},
		{"config-unexpected-empty", &contracts.ConfigAbsent{Key: "FEATURE"}, config(""), contracts.StatusReviewRequired, contracts.ReasonKeyUnexpected},
		{"file-match", &contracts.FileSHA256{SHA256: digestA}, hashed(digestA), contracts.StatusUnchanged, contracts.ReasonMatch},
		{"file-change", &contracts.FileSHA256{SHA256: digestA}, hashed(digestB), contracts.StatusReviewRequired, contracts.ReasonHashChanged},
		{"patch-match", &contracts.PatchPresent{Key: "fix", SHA256: digestA}, hashed(digestA), contracts.StatusUnchanged, contracts.ReasonMatch},
		{"patch-change", &contracts.PatchPresent{Key: "fix", SHA256: digestA}, hashed(digestB), contracts.StatusReviewRequired, contracts.ReasonHashChanged},
		{"patch-missing-key", &contracts.PatchPresent{Key: "fix", SHA256: digestA}, absent(), contracts.StatusReviewRequired, contracts.ReasonKeyMissing},
		{"patch-absence-match", &contracts.PatchAbsent{Key: "fix"}, absent(), contracts.StatusUnchanged, contracts.ReasonMatch},
		{"patch-unexpected", &contracts.PatchAbsent{Key: "fix"}, hashed(digestA), contracts.StatusReviewRequired, contracts.ReasonKeyUnexpected},
	}
	// Every expectation variant must preserve each ordinary evidence failure.
	for _, expectation := range []contracts.Expectation{
		&contracts.ConfigPresent{Key: "FEATURE", Value: "n"}, &contracts.ConfigAbsent{Key: "FEATURE"},
		&contracts.FileSHA256{SHA256: digestA}, &contracts.PatchPresent{Key: "fix", SHA256: digestA}, &contracts.PatchAbsent{Key: "fix"},
	} {
		for _, reason := range []contracts.ReasonCode{
			contracts.ReasonEvidenceMissing, contracts.ReasonEvidenceUnreadable, contracts.ReasonInvalidExport,
			contracts.ReasonUnsafePath, contracts.ReasonUnsupportedFileKind, contracts.ReasonLimitExceeded, contracts.ReasonEvidenceChanged,
		} {
			cases = append(cases, struct {
				name     string
				expect   contracts.Expectation
				observed contracts.Observation
				status   contracts.Status
				reason   contracts.ReasonCode
			}{fmt.Sprintf("%T/%s", expectation, reason), expectation, unavailable(reason), contracts.StatusUnverifiable, reason})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := manifest(contracts.Assumption{ID: "assumption", Path: "declared-evidence", Expectation: tc.expect})
			calls := 0
			report, err := evaluate.Evaluate(context.Background(), m, collectorFunc(func(_ context.Context, a contracts.Assumption) (contracts.Observation, error) {
				calls++
				if a.ID != "assumption" || a.Path != "declared-evidence" || a.Expectation != tc.expect {
					t.Fatal("collector did not receive the declared assumption")
				}
				return tc.observed, nil
			}))
			if err != nil || calls != 1 {
				t.Fatalf("Evaluate: calls=%d err=%v", calls, err)
			}
			decision := report.Decisions[0]
			result := decision.Assumptions[0]
			if result.Status != tc.status || result.Reason != tc.reason || decision.Status != tc.status || report.Status != tc.status {
				t.Fatalf("wrong verdict: %#v; decision=%s report=%s", result, decision.Status, report.Status)
			}
			if !reflect.DeepEqual(result.Observed, tc.observed) {
				t.Fatalf("observation lost: got %#v, want %#v", result.Observed, tc.observed)
			}
			if result.ID != "assumption" || result.Path != "declared-evidence" || result.Kind != tc.expect.Kind() || result.Expected.Present == nil {
				t.Fatalf("declared evidence lost: %#v", result)
			}
			if report.SchemaVersion != 1 || decision.CVE != m.Decisions[0].CVE || decision.Baseline != "release-1" || decision.Rationale != "Synthetic human decision." {
				t.Fatal("historical decision context lost")
			}
			var wantCounts contracts.Counts
			var wantReason contracts.ReasonCode
			switch tc.status {
			case contracts.StatusUnchanged:
				wantCounts.Unchanged, wantReason = 1, contracts.ReasonAllUnchanged
			case contracts.StatusReviewRequired:
				wantCounts.ReviewRequired, wantReason = 1, contracts.ReasonAssumptionsChanged
			case contracts.StatusUnverifiable:
				wantCounts.Unverifiable, wantReason = 1, contracts.ReasonEvidenceUnavailable
			}
			if report.Summary.Decisions != wantCounts || report.Summary.Assumptions != wantCounts || report.Reason != wantReason || decision.Reason != wantReason {
				t.Fatalf("wrong aggregation: %#v", report)
			}
		})
	}
}

func mixedManifest() contracts.Manifest {
	return contracts.Manifest{SchemaVersion: 1, Decisions: []contracts.Decision{
		{ID: "z-drift", CVE: "CVE-2024-0002", Baseline: "release-2", Rationale: "Synthetic inventory review.", Assumptions: []contracts.Assumption{
			{ID: "z-patch-missing", Path: "patches.json", Expectation: &contracts.PatchPresent{Key: "fix", SHA256: digestA}},
		}},
		{ID: "a-mixed", CVE: "CVE-2024-0001", Baseline: "release-1", Rationale: "Synthetic feature decision.", Assumptions: []contracts.Assumption{
			{ID: "c-unavailable", Path: "source.c", Expectation: &contracts.FileSHA256{SHA256: digestA}},
			{ID: "a-value", Path: "config.json", Expectation: &contracts.ConfigPresent{Key: "FEATURE_X", Value: "n"}},
			{ID: "b-same", Path: "config.json", Expectation: &contracts.ConfigAbsent{Key: "OLD"}},
		}},
	}}
}

func mixedCollector(_ context.Context, a contracts.Assumption) (contracts.Observation, error) {
	switch a.ID {
	case "a-value":
		return config("y"), nil
	case "b-same", "z-patch-missing":
		return absent(), nil
	case "c-unavailable":
		return unavailable(contracts.ReasonEvidenceMissing), nil
	default:
		return contracts.Observation{}, fmt.Errorf("unexpected test assumption %q", a.ID)
	}
}

func TestEvaluateMixedRetentionAndSorting(t *testing.T) {
	m := mixedManifest()
	var calls []string
	got, err := evaluate.Evaluate(context.Background(), m, collectorFunc(func(ctx context.Context, a contracts.Assumption) (contracts.Observation, error) {
		calls = append(calls, a.ID)
		return mixedCollector(ctx, a)
	}))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../testdata/evaluate/mixed-report.json")
	if err != nil {
		t.Fatal(err)
	}
	var want contracts.Report
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		pretty, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("mixed report lost evidence or precedence:\n%s", pretty)
	}
	if !reflect.DeepEqual(calls, []string{"a-value", "b-same", "c-unavailable", "z-patch-missing"}) {
		t.Fatalf("observations skipped or reordered nondeterministically: %v", calls)
	}
	if m.Decisions[0].ID != "z-drift" || m.Decisions[1].Assumptions[0].ID != "c-unavailable" {
		t.Fatal("input slices were reordered")
	}
	// Reordering the same declarations cannot change the evaluated report.
	m.Decisions[0], m.Decisions[1] = m.Decisions[1], m.Decisions[0]
	a := m.Decisions[0].Assumptions
	a[0], a[2] = a[2], a[0]
	again, err := evaluate.Evaluate(context.Background(), m, collectorFunc(mixedCollector))
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("reordered input changed report: %v", err)
	}
	firstBytes, _ := json.Marshal(got)
	secondBytes, _ := json.Marshal(again)
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("repeated evaluations are not byte-identical when serialized")
	}
}

func TestEvaluateRejectsInvalidManifestsBeforeCollection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*contracts.Manifest)
	}{
		{"unsupported-version", func(m *contracts.Manifest) { m.SchemaVersion = 2 }},
		{"no-decisions", func(m *contracts.Manifest) { m.Decisions = nil }},
		{"duplicate-decisions", func(m *contracts.Manifest) { m.Decisions = append(m.Decisions, m.Decisions[0]) }},
		{"duplicate-assumptions", func(m *contracts.Manifest) {
			m.Decisions[0].Assumptions = append(m.Decisions[0].Assumptions, m.Decisions[0].Assumptions[0])
		}},
		{"duplicate-assumptions-across-decisions", func(m *contracts.Manifest) {
			d := m.Decisions[0]
			d.ID = "other-decision"
			m.Decisions = append(m.Decisions, d)
		}},
		{"nil-expectation", func(m *contracts.Manifest) { m.Decisions[0].Assumptions[0].Expectation = nil }},
		{"typed-nil-expectation", func(m *contracts.Manifest) {
			var e *contracts.ConfigAbsent
			m.Decisions[0].Assumptions[0].Expectation = e
		}},
		{"malformed-digest", func(m *contracts.Manifest) {
			m.Decisions[0].Assumptions[0].Expectation = &contracts.FileSHA256{SHA256: "invalid"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := manifest(contracts.Assumption{ID: "a", Path: "config.json", Expectation: &contracts.ConfigAbsent{Key: "FEATURE"}})
			tc.mutate(&m)
			got, err := evaluate.Evaluate(context.Background(), m, collectorFunc(func(context.Context, contracts.Assumption) (contracts.Observation, error) {
				t.Fatal("invalid manifest reached collector")
				return absent(), nil
			}))
			if err == nil || !reflect.DeepEqual(got, contracts.Report{}) {
				t.Fatalf("invalid manifest returned a report: %#v %v", got, err)
			}
		})
	}
}

func TestEvaluateRejectsInvalidObservations(t *testing.T) {
	cases := []struct {
		name     string
		expect   contracts.Expectation
		observed contracts.Observation
	}{
		{"zero-state", &contracts.ConfigAbsent{}, contracts.Observation{}},
		{"unknown-state", &contracts.ConfigAbsent{}, contracts.Observation{State: "unknown"}},
		{"config-nil-value", &contracts.ConfigPresent{}, contracts.Observation{State: contracts.ObservationPresent}},
		{"config-digest", &contracts.ConfigPresent{}, hashed(digestA)},
		{"config-both-payloads", &contracts.ConfigPresent{}, contracts.Observation{State: contracts.ObservationPresent, Value: str(""), SHA256: str(digestA)}},
		{"present-with-reason", &contracts.ConfigPresent{}, contracts.Observation{State: contracts.ObservationPresent, Value: str(""), Reason: contracts.ReasonEvidenceMissing}},
		{"file-with-value", &contracts.FileSHA256{SHA256: digestA}, config("")},
		{"file-nil-digest", &contracts.FileSHA256{SHA256: digestA}, contracts.Observation{State: contracts.ObservationPresent}},
		{"file-malformed-digest", &contracts.FileSHA256{SHA256: digestA}, hashed(strings.Repeat("A", 64))},
		{"file-absent-state", &contracts.FileSHA256{SHA256: digestA}, absent()},
		{"patch-with-value", &contracts.PatchPresent{SHA256: digestA}, config("")},
		{"patch-nil-digest", &contracts.PatchPresent{SHA256: digestA}, contracts.Observation{State: contracts.ObservationPresent}},
		{"absent-with-value", &contracts.ConfigAbsent{}, contracts.Observation{State: contracts.ObservationAbsent, Value: str("")}},
		{"absent-with-digest", &contracts.PatchAbsent{}, contracts.Observation{State: contracts.ObservationAbsent, SHA256: str(digestA)}},
		{"absent-with-reason", &contracts.ConfigAbsent{}, contracts.Observation{State: contracts.ObservationAbsent, Reason: contracts.ReasonEvidenceMissing}},
		{"unavailable-with-value", &contracts.ConfigAbsent{}, contracts.Observation{State: contracts.ObservationUnavailable, Value: str(""), Reason: contracts.ReasonEvidenceMissing}},
		{"unavailable-with-digest", &contracts.PatchAbsent{}, contracts.Observation{State: contracts.ObservationUnavailable, SHA256: str(digestA), Reason: contracts.ReasonEvidenceMissing}},
		{"unavailable-no-reason", &contracts.ConfigAbsent{}, unavailable("")},
		{"unavailable-unknown-reason", &contracts.ConfigAbsent{}, unavailable("custom")},
		{"unavailable-comparison-reason", &contracts.ConfigAbsent{}, unavailable(contracts.ReasonMatch)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := manifest(contracts.Assumption{ID: "a", Path: "evidence", Expectation: tc.expect})
			got, err := evaluate.Evaluate(context.Background(), m, collectorFunc(func(context.Context, contracts.Assumption) (contracts.Observation, error) {
				return tc.observed, nil
			}))
			if err == nil || !reflect.DeepEqual(got, contracts.Report{}) {
				t.Fatalf("invalid observation returned a report: %#v %v", got, err)
			}
		})
	}
}

func TestEvaluateErrorsAndCancellation(t *testing.T) {
	m := manifest(
		contracts.Assumption{ID: "a", Path: "config.json", Expectation: &contracts.ConfigAbsent{Key: "A"}},
		contracts.Assumption{ID: "b", Path: "config.json", Expectation: &contracts.ConfigAbsent{Key: "B"}},
	)
	for _, want := range []error{context.Canceled, context.DeadlineExceeded, errors.New("adapter failed")} {
		calls := 0
		got, err := evaluate.Evaluate(context.Background(), m, collectorFunc(func(context.Context, contracts.Assumption) (contracts.Observation, error) {
			calls++
			if calls == 2 {
				return contracts.Observation{}, want
			}
			return absent(), nil
		}))
		if !errors.Is(err, want) || !reflect.DeepEqual(got, contracts.Report{}) || calls != 2 {
			t.Fatalf("collector error swallowed or partial report leaked: %#v %v calls=%d", got, err, calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := evaluate.Evaluate(ctx, m, collectorFunc(func(context.Context, contracts.Assumption) (contracts.Observation, error) {
		t.Fatal("already canceled evaluation collected evidence")
		return absent(), nil
	}))
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, contracts.Report{}) {
		t.Fatalf("pre-cancellation: %#v %v", got, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	got, err = evaluate.Evaluate(ctx, m, collectorFunc(func(_ context.Context, a contracts.Assumption) (contracts.Observation, error) {
		if a.ID == "b" {
			cancel()
		}
		return absent(), nil
	}))
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, contracts.Report{}) {
		t.Fatalf("late cancellation returned success: %#v %v", got, err)
	}
	if _, err := evaluate.Evaluate(nil, m, collectorFunc(mixedCollector)); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := evaluate.Evaluate(context.Background(), m, nil); err == nil {
		t.Fatal("nil collector accepted")
	}
}

func TestEvaluateSnapshotsEvidence(t *testing.T) {
	first := &contracts.ConfigPresent{Key: "A", Value: "a"}
	file := &contracts.FileSHA256{SHA256: digestA}
	m := manifest(
		contracts.Assumption{ID: "a", Path: "config.json", Expectation: first},
		contracts.Assumption{ID: "b", Path: "config.json", Expectation: &contracts.ConfigPresent{Key: "B", Value: "b"}},
		contracts.Assumption{ID: "c", Path: "source.c", Expectation: file},
	)
	var scratch string
	report, err := evaluate.Evaluate(context.Background(), m, collectorFunc(func(_ context.Context, a contracts.Assumption) (contracts.Observation, error) {
		scratch = a.ID
		if a.ID == "c" {
			scratch = digestA
			return contracts.Observation{State: contracts.ObservationPresent, SHA256: &scratch}, nil
		}
		return contracts.Observation{State: contracts.ObservationPresent, Value: &scratch}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	scratch, first.Key, first.Value, file.SHA256 = "overwritten", "overwritten", "overwritten", digestB
	results := report.Decisions[0].Assumptions
	if report.Status != contracts.StatusUnchanged || *results[0].Observed.Value != "a" || *results[1].Observed.Value != "b" || *results[2].Observed.SHA256 != digestA {
		t.Fatalf("collector buffer changed earlier observations: %#v", report)
	}
	if *results[0].Expected.Value != "a" || *results[0].Key != "A" || *results[2].Expected.SHA256 != digestA {
		t.Fatal("report expectations alias mutable input fields")
	}
}

func TestEvaluateConcurrentRuns(t *testing.T) {
	m := mixedManifest()
	want, err := evaluate.Evaluate(context.Background(), m, collectorFunc(mixedCollector))
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			got, err := evaluate.Evaluate(context.Background(), m, collectorFunc(mixedCollector))
			if err != nil || !reflect.DeepEqual(want, got) {
				t.Errorf("concurrent evaluation changed result: %v", err)
			}
		})
	}
	group.Wait()
}
