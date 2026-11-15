//go:build linux

package triageguard_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/firmdura/triageguard/pkg/triageguard"
)

func checkInputs(t *testing.T) (triageguard.Manifest, string) {
	t.Helper()
	data, err := os.ReadFile("../../testdata/integration/decisions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := triageguard.LoadManifest(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	entries, err := os.ReadDir("../../testdata/integration/evidence")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join("../../testdata/integration/evidence", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, entry.Name()), data, 0400); err != nil {
			t.Fatal(err)
		}
	}
	return m, root
}

func checkSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := filepath.Join(root, entry.Name())
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name()] = fmt.Sprintf("%x:%v:%v", sha256.Sum256(data), info.Mode(), info.ModTime())
	}
	return snapshot
}

func TestCheckRealEvidence(t *testing.T) {
	for _, test := range []struct {
		name               string
		change             func(*testing.T, string)
		status             triageguard.Status
		drift, unavailable int
	}{
		{name: "unchanged", status: triageguard.StatusUnchanged},
		{name: "config-drift", change: func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config.json"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"FEATURE_X":"y","EMPTY":""}`), 0400); err != nil {
				t.Fatal(err)
			}
		}, status: triageguard.StatusReviewRequired, drift: 1},
		{name: "mixed", change: func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config.json"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"FEATURE_X":"y","EMPTY":""}`), 0400); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, "source.c")); err != nil {
				t.Fatal(err)
			}
		}, status: triageguard.StatusUnverifiable, drift: 1, unavailable: 1},
		{name: "invalid-export", change: func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "config.json"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"FEATURE_X":"n","FEATURE_X":"n"}`), 0400); err != nil {
				t.Fatal(err)
			}
		}, status: triageguard.StatusUnverifiable, unavailable: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, root := checkInputs(t)
			if test.change != nil {
				test.change(t, root)
			}
			before := checkSnapshot(t, root)
			report, err := triageguard.Check(context.Background(), m, root)
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != test.status || report.Summary.Assumptions.ReviewRequired != test.drift || report.Summary.Assumptions.Unverifiable != test.unavailable || len(report.Decisions[0].Assumptions) != 6 {
				t.Fatalf("unexpected report: %+v", report)
			}
			if !reflect.DeepEqual(before, checkSnapshot(t, root)) {
				t.Fatal("Check changed evidence bytes/modes/mtime")
			}
			var first, second strings.Builder
			if err := triageguard.WriteJSON(&first, report); err != nil {
				t.Fatal(err)
			}
			repeated, err := triageguard.Check(context.Background(), m, root)
			if err != nil {
				t.Fatal(err)
			}
			if err := triageguard.WriteJSON(&second, repeated); err != nil {
				t.Fatal(err)
			}
			if first.String() != second.String() {
				t.Fatal("identical checks changed output")
			}
		})
	}
}

func TestCheckValidationRootAndCancellation(t *testing.T) {
	m, root := checkInputs(t)
	assertError := func(name string, ctx context.Context, manifest triageguard.Manifest, evidenceRoot string, target error) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			report, err := triageguard.Check(ctx, manifest, evidenceRoot)
			if err == nil || !reflect.DeepEqual(report, triageguard.Report{}) {
				t.Fatalf("want zero report and error, got %+v, %v", report, err)
			}
			if target != nil && !errors.Is(err, target) {
				t.Fatalf("want %v, got %v", target, err)
			}
		})
	}
	assertError("nil-context", nil, m, root, nil)
	assertError("zero-manifest", context.Background(), triageguard.Manifest{}, root, nil)
	invalid := m
	invalid.Decisions = append([]triageguard.Decision(nil), m.Decisions...)
	invalid.Decisions[0].Assumptions = append([]triageguard.Assumption(nil), m.Decisions[0].Assumptions...)
	invalid.Decisions[0].Assumptions[0].Expectation = (*triageguard.ConfigPresent)(nil)
	assertError("typed-nil-expectation", context.Background(), invalid, root, nil)
	assertError("empty-root", context.Background(), m, "", nil)
	assertError("missing-root", context.Background(), m, filepath.Join(root, "missing"), nil)
	assertError("file-root", context.Background(), m, filepath.Join(root, "config.json"), nil)
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "/", "//"} {
		assertError("symlink-root"+suffix, context.Background(), m, link+suffix, nil)
		t.Run("directory-root"+suffix, func(t *testing.T) {
			report, err := triageguard.Check(context.Background(), m, root+suffix)
			if err != nil || report.Status != triageguard.StatusUnchanged {
				t.Fatalf("directory root rejected: %+v, %v", report, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	assertError("canceled", canceled, m, root, context.Canceled)
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	assertError("deadline", deadline, m, root, context.DeadlineExceeded)
	unsafe := m
	unsafe.Decisions = append([]triageguard.Decision(nil), m.Decisions...)
	unsafe.Decisions[0].Assumptions = []triageguard.Assumption{{ID: "unsafe", Path: "../escape", Expectation: &triageguard.FileSHA256{SHA256: strings.Repeat("0", 64)}}}
	report, err := triageguard.Check(context.Background(), unsafe, root)
	if err != nil || report.Status != triageguard.StatusUnverifiable || report.Decisions[0].Assumptions[0].Reason != triageguard.ReasonUnsafePath {
		t.Fatalf("unsafe path hidden: %+v, %v", report, err)
	}
}
