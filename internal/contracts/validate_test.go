package contracts

import (
	"strings"
	"testing"
)

func validManifest(e Expectation) Manifest {
	return Manifest{SchemaVersion: SchemaVersion, Decisions: []Decision{{ID: "d", CVE: "CVE-2024-0001", Baseline: "b", Rationale: "synthetic", Assumptions: []Assumption{{ID: "a", Path: "export.json", Expectation: e}}}}}
}

func TestContractProgrammaticValidation(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, e := range []Expectation{&ConfigPresent{Key: "", Value: ""}, &ConfigAbsent{Key: ""}, &FileSHA256{digest}, &PatchPresent{"", digest}, &PatchAbsent{""}} {
		if err := ValidateManifest(validManifest(e)); err != nil {
			t.Fatalf("valid %T: %v", e, err)
		}
	}
	var configNil *ConfigPresent
	var absentNil *ConfigAbsent
	var fileNil *FileSHA256
	var patchNil *PatchPresent
	var patchAbsentNil *PatchAbsent
	for _, e := range []Expectation{nil, configNil, absentNil, fileNil, patchNil, patchAbsentNil, &FileSHA256{"bad"}, &PatchPresent{"fix", strings.Repeat("A", 64)}} {
		if err := ValidateManifest(validManifest(e)); err == nil {
			t.Fatalf("invalid %T accepted", e)
		}
	}
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.SchemaVersion = 2 }, func(m *Manifest) { m.Decisions = nil },
		func(m *Manifest) { m.Decisions[0].ID = " " }, func(m *Manifest) { m.Decisions[0].CVE = "CVE-24-0001" },
		func(m *Manifest) { m.Decisions[0].Baseline = "" }, func(m *Manifest) { m.Decisions[0].Rationale = "\n" },
		func(m *Manifest) { m.Decisions[0].Assumptions = nil }, func(m *Manifest) { m.Decisions[0].Assumptions[0].ID = "" },
		func(m *Manifest) { m.Decisions[0].Assumptions[0].Path = "" },
		func(m *Manifest) { m.Decisions = append(m.Decisions, m.Decisions[0]) },
		func(m *Manifest) {
			m.Decisions[0].Assumptions = append(m.Decisions[0].Assumptions, m.Decisions[0].Assumptions[0])
		},
	} {
		m := validManifest(&ConfigAbsent{Key: "FEATURE"})
		mutate(&m)
		if err := ValidateManifest(m); err == nil {
			t.Fatal("invalid programmatic manifest accepted")
		}
	}
}

func TestContractExpectationFields(t *testing.T) {
	value := &ConfigPresent{Key: "", Value: ""}
	kind, key, expected, err := ExpectationFields(value)
	if err != nil || kind != KindConfig || key == nil || *key != "" || expected.Present == nil || !*expected.Present || expected.Value == nil || *expected.Value != "" || expected.SHA256 != nil {
		t.Fatalf("empty string lost: %v %v %#v %v", kind, key, expected, err)
	}
	*key = "changed"
	*expected.Value = "changed"
	*expected.Present = false
	if value.Key != "" || value.Value != "" {
		t.Fatal("returned fields alias manifest")
	}
	_, _, absent, err := ExpectationFields(&ConfigAbsent{Key: "FEATURE"})
	if err != nil || absent.Present == nil || *absent.Present || absent.Value != nil || absent.SHA256 != nil {
		t.Fatalf("absence lost: %#v %v", absent, err)
	}
	if !ValidSHA256(strings.Repeat("0", 64)) || ValidSHA256(strings.Repeat("A", 64)) || ValidSHA256(strings.Repeat("0", 63)) || ValidSHA256(strings.Repeat("z", 64)) {
		t.Fatal("invalid digest validation")
	}
}
