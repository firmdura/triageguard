package triageguard_test

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/triageguard/pkg/triageguard"
	"go.yaml.in/yaml/v3"
)

func TestManifestValidRoundTrip(t *testing.T) {
	data, err := os.ReadFile("../../testdata/contracts/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := triageguard.LoadManifest(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Decisions) != 1 || len(m.Decisions[0].Assumptions) != 6 {
		t.Fatalf("incomplete manifest: %#v", m)
	}
	assumptions := m.Decisions[0].Assumptions
	if v, ok := assumptions[1].Expectation.(*triageguard.ConfigPresent); !ok || v.Key != "" || v.Value != "" {
		t.Fatalf("explicit empty value lost: %#v", assumptions[1])
	}
	if _, ok := assumptions[2].Expectation.(*triageguard.ConfigAbsent); !ok {
		t.Fatalf("absence lost: %#v", assumptions[2])
	}
	if _, ok := assumptions[3].Expectation.(*triageguard.FileSHA256); !ok {
		t.Fatal("file variant lost")
	}
	if _, ok := assumptions[4].Expectation.(*triageguard.PatchPresent); !ok {
		t.Fatal("patch-present variant lost")
	}
	if _, ok := assumptions[5].Expectation.(*triageguard.PatchAbsent); !ok {
		t.Fatal("patch-absent variant lost")
	}
	encoded, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := triageguard.LoadManifest(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("round trip: %v\n%s", err, encoded)
	}
	if !reflect.DeepEqual(m, roundTrip) {
		t.Fatalf("round trip changed manifest:\n%#v\n%#v", m, roundTrip)
	}
}

func TestManifestRejections(t *testing.T) {
	files, err := filepath.Glob("../../testdata/contracts/reject/*.yaml")
	if err != nil || len(files) < 60 {
		t.Fatalf("missing rejection fixtures: %v (%d)", err, len(files))
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".yaml"), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) > 4096 {
				t.Fatalf("fixture is not bounded: %d", len(data))
			}
			m, err := triageguard.LoadManifest(strings.NewReader(string(data)))
			if err == nil {
				t.Fatalf("accepted invalid manifest:\n%s", data)
			}
			if !reflect.DeepEqual(m, triageguard.Manifest{}) {
				t.Fatalf("error returned a partial manifest: %#v", m)
			}
		})
	}
}

func TestManifestSequenceTags(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile("../../testdata/contracts/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	want, err := triageguard.LoadManifest(strings.NewReader(string(read("valid.yaml"))))
	if err != nil {
		t.Fatal(err)
	}
	got, err := triageguard.LoadManifest(strings.NewReader(string(read("valid-explicit-sequences.yaml"))))
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatalf("explicit !!seq changed valid manifest: %v", err)
	}
	for _, field := range []string{"decisions", "assumptions"} {
		for _, tag := range []string{"str", "map", "custom"} {
			name := "reject/" + field + "-tag-" + tag + ".yaml"
			_, err := triageguard.LoadManifest(strings.NewReader(string(read(name))))
			if err == nil || !strings.Contains(err.Error(), field+" must be a sequence") {
				t.Fatalf("%s: expected sequence type rejection, got %v", name, err)
			}
		}
	}
}

func TestManifestEvidencePathDeferred(t *testing.T) {
	data, err := os.ReadFile("../../testdata/contracts/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../outside", "/absolute", "a/../b", "a//b", "a\\b"} {
		m, err := triageguard.LoadManifest(strings.NewReader(strings.Replace(string(data), "path: config.json", "path: '"+path+"'", 1)))
		if err != nil {
			t.Fatalf("path %q should reach collector as unverifiable: %v", path, err)
		}
		if m.Decisions[0].Assumptions[0].Path != path {
			t.Fatal("path silently normalized")
		}
	}
}

func TestManifestLimitsAndReadErrors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/contracts/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// YAML comments let the exact byte boundary remain an otherwise valid input.
	atLimit := string(data) + "#" + strings.Repeat("x", int(triageguard.MaxManifestBytes)-len(data)-1)
	if _, err := triageguard.LoadManifest(strings.NewReader(atLimit)); err != nil {
		t.Fatalf("exact limit rejected: %v", err)
	}
	r := &countingReader{Reader: strings.NewReader(atLimit + "x" + strings.Repeat("x", 100))}
	if _, err := triageguard.LoadManifest(r); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize: %v", err)
	}
	if r.n != triageguard.MaxManifestBytes+1 {
		t.Fatalf("unbounded read: %d", r.n)
	}
	want := errors.New("synthetic reader error")
	if _, err := triageguard.LoadManifest(failingReader{want}); !errors.Is(err, want) {
		t.Fatalf("reader error lost: %v", err)
	}
	if _, err := triageguard.LoadManifest(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
}

type countingReader struct {
	io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += int64(n)
	return n, err
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestContractExternalAliases(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	module := "module example.test/consumer\n\ngo 1.27.0\n\nrequire github.com/firmdura/triageguard v0.0.0\n\nreplace github.com/firmdura/triageguard => " + filepath.ToSlash(root) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	source := `package main
import (
 "strings"
 tg "github.com/firmdura/triageguard/pkg/triageguard"
)
func main() {
 var _ tg.Expectation = &tg.ConfigPresent{Key:"FEATURE", Value:""}
 var _ tg.Expectation = &tg.ConfigAbsent{Key:"FEATURE"}
 var _ tg.Expectation = &tg.FileSHA256{SHA256:strings.Repeat("0",64)}
 var _ tg.Expectation = &tg.PatchPresent{Key:"fix", SHA256:strings.Repeat("0",64)}
 var _ tg.Expectation = &tg.PatchAbsent{Key:"fix"}
 _ = tg.Manifest{SchemaVersion:tg.SchemaVersion, Decisions:[]tg.Decision{{
  ID:"d", CVE:"CVE-2024-0001", Baseline:"b", Rationale:"synthetic",
  Assumptions:[]tg.Assumption{{ID:"a", Path:"config.json", Expectation:&tg.ConfigAbsent{Key:"FEATURE"}}},
 }}}
 _ = tg.Report{SchemaVersion:tg.SchemaVersion, Status:tg.StatusUnchanged, Reason:tg.ReasonAllUnchanged,
  Summary:tg.Summary{Decisions:tg.Counts{Unchanged:1}}, Decisions:[]tg.DecisionResult{{
   ID:"d", Assumptions:[]tg.AssumptionResult{{Kind:tg.KindConfig, Observed:tg.Observation{State:tg.ObservationAbsent}}},
  }}}
 if _, err := tg.LoadManifest(strings.NewReader("")); err == nil { panic("empty manifest accepted") }
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("external consumer: %v\n%s", err, out)
	}
}
