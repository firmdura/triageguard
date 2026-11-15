// Package contracts defines the shared v1 manifest, evidence and report contracts.
// It does not collect evidence, evaluate decisions, or render reports.
package contracts

import "context"

const (
	SchemaVersion          = 1
	MaxManifestBytes int64 = 1 << 20
	MaxExportBytes   int64 = 16 << 20
	MaxFileBytes     int64 = 1 << 30
)

// Kind identifies an explicitly declared source of evidence.
type Kind string

const (
	KindConfig Kind = "config"
	KindFile   Kind = "file"
	KindPatch  Kind = "patch"
)

// Manifest records historical human decisions and the assumptions to recheck.
type Manifest struct {
	SchemaVersion int        `yaml:"schema_version" json:"schema_version"`
	Decisions     []Decision `yaml:"decisions" json:"decisions"`
}

// Decision supplies the historical context for a group of assumptions.
type Decision struct {
	ID          string       `yaml:"id" json:"id"`
	CVE         string       `yaml:"cve" json:"cve"`
	Baseline    string       `yaml:"baseline" json:"baseline"`
	Rationale   string       `yaml:"rationale" json:"rationale"`
	Assumptions []Assumption `yaml:"assumptions" json:"assumptions"`
}

// Assumption names an evidence path and exactly one typed expectation.
// Path syntax and filesystem safety are checked by the collector, so an unsafe
// nonempty path becomes an unavailable observation rather than a hidden result.
type Assumption struct {
	ID          string
	Path        string
	Expectation Expectation
}

// Expectation is a closed set of pointer variants. Absence variants cannot carry
// a value or digest. A nil expectation is invalid. All variants are read-only
// during a check; callers must not mutate a manifest while it is in use.
type Expectation interface {
	Kind() Kind
	isExpectation()
}

// ConfigPresent requires a key with the exact Value, including an empty string.
type ConfigPresent struct{ Key, Value string }

func (*ConfigPresent) Kind() Kind     { return KindConfig }
func (*ConfigPresent) isExpectation() {}

// ConfigAbsent requires a key to be absent from a valid config export.
type ConfigAbsent struct{ Key string }

func (*ConfigAbsent) Kind() Kind     { return KindConfig }
func (*ConfigAbsent) isExpectation() {}

// FileSHA256 requires a regular file with the lowercase SHA-256 digest.
type FileSHA256 struct{ SHA256 string }

func (*FileSHA256) Kind() Kind     { return KindFile }
func (*FileSHA256) isExpectation() {}

// PatchPresent requires a patch ID with the exact lowercase SHA-256 digest.
type PatchPresent struct{ Key, SHA256 string }

func (*PatchPresent) Kind() Kind     { return KindPatch }
func (*PatchPresent) isExpectation() {}

// PatchAbsent requires an ID to be absent from a valid patch export. This says
// nothing about whether a patch exists in firmware outside that inventory.
type PatchAbsent struct{ Key string }

func (*PatchAbsent) Kind() Kind     { return KindPatch }
func (*PatchAbsent) isExpectation() {}

// ConfigExport is a JSON object of string values. Duplicate keys are invalid.
type ConfigExport map[string]string

// PatchExport is a JSON object of lowercase SHA-256 strings. Duplicate keys and
// malformed digests anywhere in the map are invalid.
type PatchExport map[string]string

// Status describes only whether the declared assumptions still match.
type Status string

const (
	StatusUnchanged      Status = "unchanged"
	StatusReviewRequired Status = "review-required"
	StatusUnverifiable   Status = "unverifiable"
)

// ReasonCode is a stable machine-readable explanation. It must never contain
// OS error messages, absolute paths, or other host-specific diagnostics.
type ReasonCode string

const (
	ReasonMatch               ReasonCode = "match"
	ReasonValueChanged        ReasonCode = "value-changed"
	ReasonHashChanged         ReasonCode = "hash-changed"
	ReasonKeyMissing          ReasonCode = "key-missing"
	ReasonKeyUnexpected       ReasonCode = "key-unexpected"
	ReasonEvidenceMissing     ReasonCode = "evidence-missing"
	ReasonEvidenceUnreadable  ReasonCode = "evidence-unreadable"
	ReasonInvalidExport       ReasonCode = "invalid-export"
	ReasonUnsafePath          ReasonCode = "unsafe-path"
	ReasonUnsupportedFileKind ReasonCode = "unsupported-file-kind"
	ReasonLimitExceeded       ReasonCode = "limit-exceeded"
	ReasonEvidenceChanged     ReasonCode = "evidence-changed"
	ReasonAllUnchanged        ReasonCode = "all-unchanged"
	ReasonAssumptionsChanged  ReasonCode = "assumptions-changed"
	ReasonEvidenceUnavailable ReasonCode = "evidence-unavailable"
)

// ObservationState separates an absent key in a readable export from evidence
// which could not be read or trusted. Regular file success is always present.
type ObservationState string

const (
	ObservationPresent     ObservationState = "present"
	ObservationAbsent      ObservationState = "absent"
	ObservationUnavailable ObservationState = "unavailable"
)

// Observation contains filesystem truth without any comparison verdict. Present
// config observations carry Value (even when empty); file/patch observations
// carry SHA256. Absent/unavailable observations carry neither. Reason is set only
// for unavailable observations, using an evidence failure code above.
type Observation struct {
	State  ObservationState `json:"state"`
	Value  *string          `json:"value,omitempty"`
	SHA256 *string          `json:"sha256,omitempty"`
	Reason ReasonCode       `json:"reason,omitempty"`
}

// Collector observes one assumption beneath an already pinned evidence root.
// Evidence failures are ObservationUnavailable, not returned errors. An error
// aborts a run and is reserved for context cancellation/deadline expiration.
// Implementations must not modify inputs or do network I/O. Root setup/cleanup
// belongs to the concrete collector constructor/Close, outside this interface.
type Collector interface {
	Observe(context.Context, Assumption) (Observation, error)
}

// ExpectedEvidence is the explicit expectation displayed in a report. Present
// is always nonnil; Value is present only for config-present, SHA256 only for
// file/patch-present. A pointer preserves an explicitly empty config value.
type ExpectedEvidence struct {
	Present *bool   `json:"present"`
	Value   *string `json:"value,omitempty"`
	SHA256  *string `json:"sha256,omitempty"`
}

// AssumptionResult preserves one expected/observed comparison, including failures.
type AssumptionResult struct {
	ID       string           `json:"id"`
	Kind     Kind             `json:"kind"`
	Path     string           `json:"path"`
	Key      *string          `json:"key,omitempty"`
	Expected ExpectedEvidence `json:"expected"`
	Observed Observation      `json:"observed"`
	Status   Status           `json:"status"`
	Reason   ReasonCode       `json:"reason"`
}

// DecisionResult preserves historical context and every assumption observation.
type DecisionResult struct {
	ID          string             `json:"id"`
	CVE         string             `json:"cve"`
	Baseline    string             `json:"baseline"`
	Rationale   string             `json:"rationale"`
	Status      Status             `json:"status"`
	Reason      ReasonCode         `json:"reason"`
	Assumptions []AssumptionResult `json:"assumptions"`
}

// Counts counts results at one level. The three fields sum to that level's size.
type Counts struct {
	Unchanged      int `json:"unchanged"`
	ReviewRequired int `json:"review_required"`
	Unverifiable   int `json:"unverifiable"`
}

// Summary counts decisions and assumptions separately.
type Summary struct {
	Decisions   Counts `json:"decisions"`
	Assumptions Counts `json:"assumptions"`
}

// Report is deterministic evidence for human reassessment, not a vulnerability
// applicability, remediation, or compliance verdict. Decisions and assumptions
// are sorted by ID. Unverifiable takes precedence over review-required, which
// takes precedence over unchanged, without dropping any observations.
type Report struct {
	SchemaVersion int              `json:"schema_version"`
	Status        Status           `json:"status"`
	Reason        ReasonCode       `json:"reason"`
	Summary       Summary          `json:"summary"`
	Decisions     []DecisionResult `json:"decisions"`
}
