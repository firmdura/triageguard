// Package triageguard rechecks explicitly declared evidence behind historical
// human CVE decisions. Unchanged assumptions do not establish CVE applicability,
// remediation, security, or compliance. Inputs must remain quiescent during use.
package triageguard

import "github.com/firmdura/triageguard/internal/contracts"

type (
	// Manifest records historical human decisions and the assumptions to recheck.
	Manifest = contracts.Manifest
	// Decision groups assumptions with an ID, CVE, baseline and human rationale.
	Decision = contracts.Decision
	// Assumption declares a relative evidence path and exactly one typed expectation.
	Assumption = contracts.Assumption
	// Expectation accepts only nonnil pointers to the five exported expectation variants.
	Expectation = contracts.Expectation
	// ConfigPresent requires Key to have the exact Value, including an empty string.
	ConfigPresent = contracts.ConfigPresent
	// ConfigAbsent requires Key to be absent from a valid readable config export.
	ConfigAbsent = contracts.ConfigAbsent
	// FileSHA256 requires a regular file with the declared lowercase SHA-256 digest.
	FileSHA256 = contracts.FileSHA256
	// PatchPresent requires Key to map to SHA256 in a valid patch inventory.
	PatchPresent = contracts.PatchPresent
	// PatchAbsent requires an inventory key to be absent; it makes no firmware claim.
	PatchAbsent = contracts.PatchAbsent
	// ConfigExport describes a JSON object of strings; duplicate JSON keys are invalid.
	ConfigExport = contracts.ConfigExport
	// PatchExport describes a JSON object of lowercase SHA-256 strings.
	PatchExport = contracts.PatchExport
	// Kind identifies a declared config, file or patch-inventory evidence source.
	Kind = contracts.Kind
	// Status describes only whether the declared assumptions still match.
	Status = contracts.Status
	// ReasonCode is a stable machine-readable comparison or evidence-failure reason.
	ReasonCode = contracts.ReasonCode
	// ObservationState distinguishes present evidence, an absent key and unavailable evidence.
	ObservationState = contracts.ObservationState
	// Observation holds a read result; only unavailable observations carry a Reason.
	Observation = contracts.Observation
	// ExpectedEvidence preserves presence and optional value/hash pointers in reports.
	ExpectedEvidence = contracts.ExpectedEvidence
	// AssumptionResult preserves one expected/observed comparison, including failures.
	AssumptionResult = contracts.AssumptionResult
	// DecisionResult preserves historical context and every assumption result.
	DecisionResult = contracts.DecisionResult
	// Counts counts unchanged, review-required and unverifiable results at one level.
	Counts = contracts.Counts
	// Summary counts decisions and assumptions separately.
	Summary = contracts.Summary
	// Report contains sorted results for human reassessment, not a CVE applicability verdict.
	Report = contracts.Report
)

const (
	// SchemaVersion is the supported manifest and report schema version, 1.
	SchemaVersion = contracts.SchemaVersion
	// MaxManifestBytes bounds a YAML manifest to 1 MiB.
	MaxManifestBytes = contracts.MaxManifestBytes
	// MaxExportBytes bounds each config or patch JSON export to 16 MiB.
	MaxExportBytes = contracts.MaxExportBytes
	// MaxFileBytes bounds each regular file hash to 1 GiB.
	MaxFileBytes = contracts.MaxFileBytes
	// KindConfig identifies an exported JSON config string.
	KindConfig = contracts.KindConfig
	// KindFile identifies a regular file SHA-256 observation.
	KindFile = contracts.KindFile
	// KindPatch identifies an exported patch ID/SHA-256 inventory entry.
	KindPatch = contracts.KindPatch
	// StatusUnchanged means every declared assumption matches.
	StatusUnchanged = contracts.StatusUnchanged
	// StatusReviewRequired means known evidence changed and none is unavailable.
	StatusReviewRequired = contracts.StatusReviewRequired
	// StatusUnverifiable means at least one declared observation is unavailable.
	StatusUnverifiable = contracts.StatusUnverifiable
	// ObservationPresent means the declared file or key was read successfully.
	ObservationPresent = contracts.ObservationPresent
	// ObservationAbsent means a declared key is absent from a valid readable export.
	ObservationAbsent = contracts.ObservationAbsent
	// ObservationUnavailable means evidence could not be read or trusted.
	ObservationUnavailable = contracts.ObservationUnavailable
	// ReasonMatch means the observed presence/value/hash matches its expectation.
	ReasonMatch = contracts.ReasonMatch
	// ReasonValueChanged means a present config string differs from its expectation.
	ReasonValueChanged = contracts.ReasonValueChanged
	// ReasonHashChanged means a present file or patch digest differs from its expectation.
	ReasonHashChanged = contracts.ReasonHashChanged
	// ReasonKeyMissing means an expected key is absent from a valid export.
	ReasonKeyMissing = contracts.ReasonKeyMissing
	// ReasonKeyUnexpected means an expected absent key is present in a valid export.
	ReasonKeyUnexpected = contracts.ReasonKeyUnexpected
	// ReasonEvidenceMissing means the declared evidence file does not exist.
	ReasonEvidenceMissing = contracts.ReasonEvidenceMissing
	// ReasonEvidenceUnreadable means an evidence open/read/stat operation failed.
	ReasonEvidenceUnreadable = contracts.ReasonEvidenceUnreadable
	// ReasonInvalidExport means a config or patch export violates the JSON schema.
	ReasonInvalidExport = contracts.ReasonInvalidExport
	// ReasonUnsafePath means an evidence path has forbidden syntax or a symlink component.
	ReasonUnsafePath = contracts.ReasonUnsafePath
	// ReasonUnsupportedFileKind means evidence is not a regular file.
	ReasonUnsupportedFileKind = contracts.ReasonUnsupportedFileKind
	// ReasonLimitExceeded means evidence exceeds its byte bound.
	ReasonLimitExceeded = contracts.ReasonLimitExceeded
	// ReasonEvidenceChanged means size or mtime changed during an evidence read.
	ReasonEvidenceChanged = contracts.ReasonEvidenceChanged
	// ReasonAllUnchanged is the decision/report reason when all assumptions match.
	ReasonAllUnchanged = contracts.ReasonAllUnchanged
	// ReasonAssumptionsChanged is the aggregate reason for known drift without unavailable evidence.
	ReasonAssumptionsChanged = contracts.ReasonAssumptionsChanged
	// ReasonEvidenceUnavailable is the aggregate reason when any evidence is unavailable.
	ReasonEvidenceUnavailable = contracts.ReasonEvidenceUnavailable
)
