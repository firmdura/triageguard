package triageguard

import (
	"bytes"
	"fmt"
	"io"

	"github.com/firmdura/triageguard/internal/contracts"
	"go.yaml.in/yaml/v3"
)

// LoadManifest reads one strict schema_version: 1 YAML document, bounded to
// MaxManifestBytes. It rejects unknown/duplicate fields, aliases, duplicate IDs,
// invalid scalar types and malformed variants. An error returns a zero Manifest.
// It does not open evidence paths or make network requests.
func LoadManifest(r io.Reader) (Manifest, error) {
	if r == nil {
		return Manifest{}, fmt.Errorf("manifest reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	if int64(len(data)) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("manifest exceeds %d bytes", MaxManifestBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return Manifest{}, fmt.Errorf("decode trailing manifest: %w", err)
		}
		return Manifest{}, fmt.Errorf("manifest must contain exactly one YAML document")
	}
	if err := rejectAliases(&document); err != nil {
		return Manifest{}, err
	}
	if len(document.Content) != 1 {
		return Manifest{}, fmt.Errorf("manifest must be a mapping")
	}
	root, err := object(document.Content[0], "schema_version", "decisions")
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	version := root["schema_version"]
	if version == nil || version.Kind != yaml.ScalarNode || version.Tag != "!!int" {
		return Manifest{}, fmt.Errorf("schema_version must be an integer")
	}
	var m Manifest
	if err := version.Decode(&m.SchemaVersion); err != nil {
		return Manifest{}, fmt.Errorf("schema_version: %w", err)
	}
	decisions := root["decisions"]
	if decisions == nil || decisions.Kind != yaml.SequenceNode || decisions.Tag != "!!seq" {
		return Manifest{}, fmt.Errorf("decisions must be a sequence")
	}
	for i, node := range decisions.Content {
		d, err := decodeDecision(node)
		if err != nil {
			return Manifest{}, fmt.Errorf("decision %d: %w", i+1, err)
		}
		m.Decisions = append(m.Decisions, d)
	}
	if err := contracts.ValidateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func rejectAliases(root *yaml.Node) error {
	stack := []*yaml.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Kind == yaml.AliasNode {
			return fmt.Errorf("YAML aliases are not allowed")
		}
		stack = append(stack, n.Content...)
	}
	return nil
}

func object(n *yaml.Node, allowed ...string) (map[string]*yaml.Node, error) {
	if n.Kind != yaml.MappingNode || n.Tag != "!!map" {
		return nil, fmt.Errorf("expected a mapping")
	}
	fields := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, fmt.Errorf("line %d, column %d: mapping keys must be strings", key.Line, key.Column)
		}
		// Previous keys are distinct members of the small allowed field list.
		for j := 0; j < i; j += 2 {
			if first := n.Content[j]; first.Value == key.Value {
				return nil, fmt.Errorf("line %d, column %d: duplicate field %q (first at line %d, column %d)",
					key.Line, key.Column, key.Value, first.Line, first.Column)
			}
		}
		known := false
		for _, name := range allowed {
			if key.Value == name {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("line %d, column %d: unknown field %q", key.Line, key.Column, key.Value)
		}
		fields[key.Value] = n.Content[i+1]
	}
	return fields, nil
}

func stringField(fields map[string]*yaml.Node, name string) (string, error) {
	n := fields[name]
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", fmt.Errorf("%s must be an explicitly supplied string", name)
	}
	return n.Value, nil
}

func decodeDecision(n *yaml.Node) (Decision, error) {
	fields, err := object(n, "id", "cve", "baseline", "rationale", "assumptions")
	if err != nil {
		return Decision{}, err
	}
	var d Decision
	for _, f := range []struct {
		name string
		dst  *string
	}{{"id", &d.ID}, {"cve", &d.CVE}, {"baseline", &d.Baseline}, {"rationale", &d.Rationale}} {
		*f.dst, err = stringField(fields, f.name)
		if err != nil {
			return Decision{}, err
		}
	}
	assumptions := fields["assumptions"]
	if assumptions == nil || assumptions.Kind != yaml.SequenceNode || assumptions.Tag != "!!seq" {
		return Decision{}, fmt.Errorf("assumptions must be a sequence")
	}
	for i, node := range assumptions.Content {
		a, err := decodeAssumption(node)
		if err != nil {
			return Decision{}, fmt.Errorf("assumption %d: %w", i+1, err)
		}
		d.Assumptions = append(d.Assumptions, a)
	}
	return d, nil
}

func decodeAssumption(n *yaml.Node) (Assumption, error) {
	fields, err := object(n, "id", "kind", "path", "key", "expected_present", "expected_value", "expected_sha256")
	if err != nil {
		return Assumption{}, err
	}
	var a Assumption
	a.ID, err = stringField(fields, "id")
	if err != nil {
		return Assumption{}, err
	}
	a.Path, err = stringField(fields, "path")
	if err != nil {
		return Assumption{}, err
	}
	kind, err := stringField(fields, "kind")
	if err != nil {
		return Assumption{}, err
	}
	if Kind(kind) == KindFile {
		for _, name := range []string{"key", "expected_present", "expected_value"} {
			if fields[name] != nil {
				return Assumption{}, fmt.Errorf("%s is forbidden for file assumptions", name)
			}
		}
		digest, err := stringField(fields, "expected_sha256")
		if err != nil {
			return Assumption{}, err
		}
		a.Expectation = &FileSHA256{SHA256: digest}
		return a, nil
	}
	if Kind(kind) != KindConfig && Kind(kind) != KindPatch {
		return Assumption{}, fmt.Errorf("unsupported assumption kind %q", kind)
	}
	key, err := stringField(fields, "key")
	if err != nil {
		return Assumption{}, err
	}
	presentNode := fields["expected_present"]
	if presentNode == nil || presentNode.Kind != yaml.ScalarNode || presentNode.Tag != "!!bool" {
		return Assumption{}, fmt.Errorf("expected_present must be an explicitly supplied boolean")
	}
	var present bool
	if err := presentNode.Decode(&present); err != nil {
		return Assumption{}, err
	}
	valueField, forbidden := "expected_value", "expected_sha256"
	if Kind(kind) == KindPatch {
		valueField, forbidden = forbidden, valueField
	}
	if fields[forbidden] != nil {
		return Assumption{}, fmt.Errorf("%s is forbidden for %s assumptions", forbidden, kind)
	}
	if !present {
		if fields[valueField] != nil {
			return Assumption{}, fmt.Errorf("%s is forbidden when expected_present is false", valueField)
		}
		if Kind(kind) == KindConfig {
			a.Expectation = &ConfigAbsent{Key: key}
		} else {
			a.Expectation = &PatchAbsent{Key: key}
		}
		return a, nil
	}
	value, err := stringField(fields, valueField)
	if err != nil {
		return Assumption{}, err
	}
	if Kind(kind) == KindConfig {
		a.Expectation = &ConfigPresent{Key: key, Value: value}
	} else {
		a.Expectation = &PatchPresent{Key: key, SHA256: value}
	}
	return a, nil
}
