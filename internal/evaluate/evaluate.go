// Package evaluate compares declared expectations with collector observations.
// It does not access the filesystem, render reports, or determine CVE applicability.
package evaluate

import (
	"context"
	"fmt"
	"sort"

	"github.com/firmdura/triageguard/internal/contracts"
)

// Evaluate observes every assumption and returns the comparisons in ID order.
// Unavailable evidence takes precedence over drift without hiding either result.
// Ordinary evidence failures belong in observations; malformed manifests,
// invalid collector observations, collector errors, and cancellation return a
// zero report and an error. It never mutates the manifest or collector payloads.
func Evaluate(ctx context.Context, manifest contracts.Manifest, collector contracts.Collector) (contracts.Report, error) {
	if err := contracts.ValidateManifest(manifest); err != nil {
		return contracts.Report{}, err
	}
	if ctx == nil {
		return contracts.Report{}, fmt.Errorf("evaluation context is nil")
	}
	if err := ctx.Err(); err != nil {
		return contracts.Report{}, err
	}
	if collector == nil {
		return contracts.Report{}, fmt.Errorf("evidence collector is nil")
	}

	decisions := append([]contracts.Decision(nil), manifest.Decisions...)
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].ID < decisions[j].ID })
	report := contracts.Report{
		SchemaVersion: contracts.SchemaVersion,
		Status:        contracts.StatusUnchanged,
		Decisions:     make([]contracts.DecisionResult, 0, len(decisions)),
	}
	for _, decision := range decisions {
		assumptions := append([]contracts.Assumption(nil), decision.Assumptions...)
		sort.Slice(assumptions, func(i, j int) bool { return assumptions[i].ID < assumptions[j].ID })
		result := contracts.DecisionResult{
			ID: decision.ID, CVE: decision.CVE, Baseline: decision.Baseline, Rationale: decision.Rationale,
			Status:      contracts.StatusUnchanged,
			Assumptions: make([]contracts.AssumptionResult, 0, len(assumptions)),
		}
		for _, assumption := range assumptions {
			if err := ctx.Err(); err != nil {
				return contracts.Report{}, err
			}
			kind, key, expected, err := contracts.ExpectationFields(assumption.Expectation)
			if err != nil {
				return contracts.Report{}, fmt.Errorf("assumption %q: %w", assumption.ID, err)
			}
			observed, err := collector.Observe(ctx, assumption)
			if err != nil {
				return contracts.Report{}, fmt.Errorf("observe assumption %q: %w", assumption.ID, err)
			}
			if err := ctx.Err(); err != nil {
				return contracts.Report{}, err
			}
			if err := validateObservation(kind, observed); err != nil {
				return contracts.Report{}, fmt.Errorf("observation for assumption %q: %w", assumption.ID, err)
			}
			observed = copyObservation(observed)
			status, reason := compare(kind, expected, observed)
			result.Assumptions = append(result.Assumptions, contracts.AssumptionResult{
				ID: assumption.ID, Kind: kind, Path: assumption.Path, Key: key,
				Expected: expected, Observed: observed, Status: status, Reason: reason,
			})
			result.Status = precedence(result.Status, status)
			count(&report.Summary.Assumptions, status)
		}
		result.Reason = aggregateReason(result.Status)
		report.Decisions = append(report.Decisions, result)
		report.Status = precedence(report.Status, result.Status)
		count(&report.Summary.Decisions, result.Status)
	}
	if err := ctx.Err(); err != nil {
		return contracts.Report{}, err
	}
	report.Reason = aggregateReason(report.Status)
	return report, nil
}

func compare(kind contracts.Kind, expected contracts.ExpectedEvidence, observed contracts.Observation) (contracts.Status, contracts.ReasonCode) {
	if observed.State == contracts.ObservationUnavailable {
		return contracts.StatusUnverifiable, observed.Reason
	}
	if observed.State == contracts.ObservationAbsent {
		if !*expected.Present {
			return contracts.StatusUnchanged, contracts.ReasonMatch
		}
		return contracts.StatusReviewRequired, contracts.ReasonKeyMissing
	}
	if !*expected.Present {
		return contracts.StatusReviewRequired, contracts.ReasonKeyUnexpected
	}
	if kind == contracts.KindConfig {
		if *expected.Value != *observed.Value {
			return contracts.StatusReviewRequired, contracts.ReasonValueChanged
		}
	} else if *expected.SHA256 != *observed.SHA256 {
		return contracts.StatusReviewRequired, contracts.ReasonHashChanged
	}
	return contracts.StatusUnchanged, contracts.ReasonMatch
}

// validateObservation keeps a broken adapter from producing an unchanged
// verdict through zero values or a payload that contradicts its declared state.
func validateObservation(kind contracts.Kind, observed contracts.Observation) error {
	switch observed.State {
	case contracts.ObservationPresent:
		if observed.Reason != "" {
			return fmt.Errorf("present evidence must not carry an unavailable reason")
		}
		if kind == contracts.KindConfig {
			if observed.Value == nil || observed.SHA256 != nil {
				return fmt.Errorf("present config evidence requires only a value")
			}
		} else if observed.Value != nil || observed.SHA256 == nil || !contracts.ValidSHA256(*observed.SHA256) {
			return fmt.Errorf("present file or patch evidence requires only a valid SHA-256")
		}
	case contracts.ObservationAbsent:
		if kind == contracts.KindFile {
			return fmt.Errorf("a missing file must be unavailable evidence")
		}
		if observed.Value != nil || observed.SHA256 != nil || observed.Reason != "" {
			return fmt.Errorf("absent evidence must not carry a payload or reason")
		}
	case contracts.ObservationUnavailable:
		if observed.Value != nil || observed.SHA256 != nil || !evidenceReason(observed.Reason) {
			return fmt.Errorf("unavailable evidence requires only an evidence failure reason")
		}
	default:
		return fmt.Errorf("unknown observation state")
	}
	return nil
}

func evidenceReason(reason contracts.ReasonCode) bool {
	switch reason {
	case contracts.ReasonEvidenceMissing, contracts.ReasonEvidenceUnreadable,
		contracts.ReasonInvalidExport, contracts.ReasonUnsafePath,
		contracts.ReasonUnsupportedFileKind, contracts.ReasonLimitExceeded,
		contracts.ReasonEvidenceChanged:
		return true
	default:
		return false
	}
}

func copyObservation(observed contracts.Observation) contracts.Observation {
	if observed.Value != nil {
		value := *observed.Value
		observed.Value = &value
	}
	if observed.SHA256 != nil {
		digest := *observed.SHA256
		observed.SHA256 = &digest
	}
	return observed
}

func precedence(a, b contracts.Status) contracts.Status {
	if a == contracts.StatusUnverifiable || b == contracts.StatusUnverifiable {
		return contracts.StatusUnverifiable
	}
	if a == contracts.StatusReviewRequired || b == contracts.StatusReviewRequired {
		return contracts.StatusReviewRequired
	}
	return contracts.StatusUnchanged
}

func aggregateReason(status contracts.Status) contracts.ReasonCode {
	switch status {
	case contracts.StatusUnverifiable:
		return contracts.ReasonEvidenceUnavailable
	case contracts.StatusReviewRequired:
		return contracts.ReasonAssumptionsChanged
	default:
		return contracts.ReasonAllUnchanged
	}
}

func count(counts *contracts.Counts, status contracts.Status) {
	switch status {
	case contracts.StatusUnchanged:
		counts.Unchanged++
	case contracts.StatusReviewRequired:
		counts.ReviewRequired++
	case contracts.StatusUnverifiable:
		counts.Unverifiable++
	}
}
