package contracts

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateManifest applies the same structural contract to decoded and
// programmatically constructed manifests. It does not access the filesystem.
func ValidateManifest(m Manifest) error {
	cvePattern := regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", m.SchemaVersion)
	}
	if len(m.Decisions) == 0 {
		return fmt.Errorf("decisions must not be empty")
	}
	type assumptionLocation struct {
		decision string
		number   int
	}
	decisionIDs := make(map[string]int)
	assumptionIDs := make(map[string]assumptionLocation)
	for di, d := range m.Decisions {
		if strings.TrimSpace(d.ID) == "" {
			return fmt.Errorf("decision id must not be empty")
		}
		if first, ok := decisionIDs[d.ID]; ok {
			return fmt.Errorf("duplicate decision id %q at decision %d (first at decision %d)", d.ID, di+1, first)
		}
		decisionIDs[d.ID] = di + 1
		if !cvePattern.MatchString(d.CVE) {
			return fmt.Errorf("decision %q: invalid CVE", d.ID)
		}
		if strings.TrimSpace(d.Baseline) == "" || strings.TrimSpace(d.Rationale) == "" {
			return fmt.Errorf("decision %q: baseline and rationale must not be empty", d.ID)
		}
		if len(d.Assumptions) == 0 {
			return fmt.Errorf("decision %q: assumptions must not be empty", d.ID)
		}
		for ai, a := range d.Assumptions {
			if strings.TrimSpace(a.ID) == "" {
				return fmt.Errorf("decision %q: assumption id must not be empty", d.ID)
			}
			if first, ok := assumptionIDs[a.ID]; ok {
				return fmt.Errorf("duplicate assumption id %q at decision %q, assumption %d (first at decision %q, assumption %d)",
					a.ID, d.ID, ai+1, first.decision, first.number)
			}
			assumptionIDs[a.ID] = assumptionLocation{decision: d.ID, number: ai + 1}
			if a.Path == "" {
				return fmt.Errorf("assumption %q: path must not be empty", a.ID)
			}
			if _, _, _, err := ExpectationFields(a.Expectation); err != nil {
				return fmt.Errorf("assumption %q: %w", a.ID, err)
			}
		}
	}
	return nil
}

// ValidSHA256 reports whether s is exactly 64 lowercase hexadecimal digits.
func ValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9') && !('a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// ExpectationFields extracts report fields from a valid typed expectation.
// Returned pointers refer to fresh scalar copies, never caller-owned fields.
func ExpectationFields(e Expectation) (Kind, *string, ExpectedEvidence, error) {
	present := true
	fields := ExpectedEvidence{Present: &present}
	var key *string
	var kind Kind
	switch v := e.(type) {
	case *ConfigPresent:
		if v == nil {
			break
		}
		kind = KindConfig
		k, value := v.Key, v.Value
		key, fields.Value = &k, &value
	case *ConfigAbsent:
		if v == nil {
			break
		}
		kind = KindConfig
		k := v.Key
		key = &k
		present = false
	case *FileSHA256:
		if v == nil {
			break
		}
		kind = KindFile
		digest := v.SHA256
		fields.SHA256 = &digest
	case *PatchPresent:
		if v == nil {
			break
		}
		kind = KindPatch
		k, digest := v.Key, v.SHA256
		key, fields.SHA256 = &k, &digest
	case *PatchAbsent:
		if v == nil {
			break
		}
		kind = KindPatch
		k := v.Key
		key = &k
		present = false
	}
	if kind == "" {
		return "", nil, ExpectedEvidence{}, fmt.Errorf("exactly one nonnil typed expectation is required")
	}
	if fields.SHA256 != nil && !ValidSHA256(*fields.SHA256) {
		return "", nil, ExpectedEvidence{}, fmt.Errorf("expected_sha256 must be 64 lowercase hexadecimal digits")
	}
	return kind, key, fields, nil
}

// MarshalYAML preserves the flat v1 YAML variants for round trips. LoadManifest
// remains the only strict YAML decoder; this method does not validate a manifest.
func (a Assumption) MarshalYAML() (any, error) {
	kind, key, expected, err := ExpectationFields(a.Expectation)
	if err != nil {
		return nil, err
	}
	var present *bool
	if kind != KindFile {
		present = expected.Present
	}
	return struct {
		ID      string  `yaml:"id"`
		Kind    Kind    `yaml:"kind"`
		Path    string  `yaml:"path"`
		Key     *string `yaml:"key,omitempty"`
		Present *bool   `yaml:"expected_present,omitempty"`
		Value   *string `yaml:"expected_value,omitempty"`
		SHA256  *string `yaml:"expected_sha256,omitempty"`
	}{a.ID, kind, a.Path, key, present, expected.Value, expected.SHA256}, nil
}
