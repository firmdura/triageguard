package triageguard_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"html"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/firmdura/triageguard/pkg/triageguard"
)

func renderFixtures(t *testing.T) map[string]triageguard.Report {
	t.Helper()
	data, err := os.ReadFile("../../testdata/reports/input.json")
	if err != nil {
		t.Fatal(err)
	}
	var reports map[string]triageguard.Report
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reports); err != nil {
		t.Fatal(err)
	}
	return reports
}

func renderWriters() map[string]func(io.Writer, triageguard.Report) error {
	return map[string]func(io.Writer, triageguard.Report) error{
		"json": triageguard.WriteJSON,
		"md":   triageguard.WriteMarkdown,
	}
}

func TestWriteReportGolden(t *testing.T) {
	for name, report := range renderFixtures(t) {
		for format, write := range renderWriters() {
			t.Run(name+"/"+format, func(t *testing.T) {
				want, err := os.ReadFile(filepath.Join("../../testdata/reports", name+"."+format))
				if err != nil {
					t.Fatal(err)
				}
				var got bytes.Buffer
				if err := write(&got, report); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want) {
					t.Fatalf("report differs from %s.%s\n%s", name, format, got.Bytes())
				}
			})
		}
	}
}

func TestReportDeterminismAndInputImmutability(t *testing.T) {
	report := renderFixtures(t)["mixed"]
	before, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewPCG(7, 11))
	for format, write := range renderWriters() {
		t.Run(format, func(t *testing.T) {
			var want bytes.Buffer
			if err := write(&want, report); err != nil {
				t.Fatal(err)
			}
			for iteration := 0; iteration < 20; iteration++ {
				// Decode a fresh copy so the test never aliases the original slices.
				var shuffled triageguard.Report
				if err := json.Unmarshal(before, &shuffled); err != nil {
					t.Fatal(err)
				}
				random.Shuffle(len(shuffled.Decisions), func(i, j int) {
					shuffled.Decisions[i], shuffled.Decisions[j] = shuffled.Decisions[j], shuffled.Decisions[i]
				})
				for i := range shuffled.Decisions {
					assumptions := shuffled.Decisions[i].Assumptions
					random.Shuffle(len(assumptions), func(i, j int) { assumptions[i], assumptions[j] = assumptions[j], assumptions[i] })
				}
				shuffledBefore, _ := json.Marshal(shuffled)
				var got bytes.Buffer
				if err := write(&got, shuffled); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want.Bytes()) {
					t.Fatalf("shuffle %d changed rendering", iteration)
				}
				shuffledAfter, _ := json.Marshal(shuffled)
				if !bytes.Equal(shuffledBefore, shuffledAfter) {
					t.Fatal("writer mutated its input")
				}
			}
		})
	}
	after, _ := json.Marshal(report)
	if !bytes.Equal(before, after) {
		t.Fatal("writer mutated caller-owned slices or pointer fields")
	}
}

func TestReportJSONEvidenceAndOrder(t *testing.T) {
	var output bytes.Buffer
	if err := triageguard.WriteJSON(&output, renderFixtures(t)["mixed"]); err != nil {
		t.Fatal(err)
	}
	// Decode into independent generic JSON objects, not a report-specific decoder.
	var report map[string]any
	decoder := json.NewDecoder(&output)
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("expected exactly one JSON report: %v", err)
	}
	if report["schema_version"] != float64(1) || report["status"] != "unverifiable" || report["reason"] != "evidence-unavailable" {
		t.Fatalf("aggregate fields lost: %#v", report)
	}
	decisions := report["decisions"].([]any)
	ids := make([]string, 0, len(decisions))
	for _, value := range decisions {
		decision := value.(map[string]any)
		ids = append(ids, decision["id"].(string))
		if _, ok := decision["rationale"]; !ok {
			t.Fatal("rationale was dropped")
		}
	}
	if !reflect.DeepEqual(ids, []string{"baseline-retained", "feature-drift", "missing-evidence"}) {
		t.Fatalf("decision order: %v", ids)
	}
	assumptions := decisions[0].(map[string]any)["assumptions"].([]any)
	absent := assumptions[0].(map[string]any)
	if absent["id"] != "absent-inventory-key" || absent["expected"].(map[string]any)["present"] != false || absent["observed"].(map[string]any)["state"] != "absent" {
		t.Fatalf("absent key semantics lost: %#v", absent)
	}
	if _, exists := absent["observed"].(map[string]any)["value"]; exists {
		t.Fatal("absent key gained a value")
	}
	empty := assumptions[1].(map[string]any)
	if empty["id"] != "empty-config" || empty["key"] != "" || empty["expected"].(map[string]any)["value"] != "" || empty["observed"].(map[string]any)["value"] != "" {
		t.Fatalf("explicit empty strings lost: %#v", empty)
	}
	file := assumptions[2].(map[string]any)
	if _, exists := file["key"]; exists {
		t.Fatal("file gained a key")
	}
	if file["expected"].(map[string]any)["sha256"] != strings.Repeat("a", 64) || file["observed"].(map[string]any)["sha256"] != strings.Repeat("a", 64) {
		t.Fatal("hash evidence lost")
	}
	missing := decisions[2].(map[string]any)["assumptions"].([]any)
	unavailable := missing[0].(map[string]any)
	if unavailable["status"] != "unverifiable" || unavailable["reason"] != "evidence-missing" || unavailable["observed"].(map[string]any)["reason"] != "evidence-missing" {
		t.Fatalf("unavailable evidence lost: %#v", unavailable)
	}
	if missing[1].(map[string]any)["status"] != "review-required" {
		t.Fatal("drift hidden by another unavailable observation")
	}
}

func TestWritePreservesSuppliedVerdictsAndCounts(t *testing.T) {
	report := renderFixtures(t)["unverifiable"]
	// A renderer displays supplied values even if a caller gives inconsistent
	// aggregate values. Only the evaluator owns status and count computation.
	report.Status = triageguard.StatusUnchanged
	report.Reason = triageguard.ReasonAllUnchanged
	report.Summary.Decisions.Unchanged = 41
	for format, write := range renderWriters() {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := write(&output, report); err != nil {
				t.Fatal(err)
			}
			if format == "json" {
				var decoded triageguard.Report
				if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
					t.Fatal(err)
				}
				if decoded.Status != report.Status || decoded.Reason != report.Reason || decoded.Summary != report.Summary {
					t.Fatal("renderer recomputed supplied verdict or counts")
				}
			} else if text := html.UnescapeString(output.String()); !strings.Contains(text, "Overall status: \"unchanged\"") || !strings.Contains(text, "Reason: All recorded assumptions match. (\"all-unchanged\")") || !strings.Contains(text, "| Decisions | 41 | 0 | 1 |") {
				t.Fatal("Markdown renderer recomputed supplied verdict or counts")
			}
		})
	}
}

func TestWriteMarkdownEscaping(t *testing.T) {
	var allASCII strings.Builder
	for r := rune(0); r < 128; r++ {
		allASCII.WriteRune(r)
	}
	payload := " \t\n## injected\r\n| bad | table |\n<script>alert('x')</script>\n[link](https://example.invalid) ![image](x) `code` **bold** &amp; &#124; café 日本語 😀\u2028\u2029" + allASCII.String()
	present := true
	report := triageguard.Report{SchemaVersion: 1, Status: triageguard.StatusUnchanged, Reason: triageguard.ReasonAllUnchanged,
		Decisions: []triageguard.DecisionResult{{ID: payload, CVE: "CVE-2024-0001", Baseline: payload, Rationale: payload, Status: triageguard.StatusUnchanged, Reason: triageguard.ReasonAllUnchanged,
			Assumptions: []triageguard.AssumptionResult{{ID: payload, Kind: triageguard.KindConfig, Path: payload, Key: &payload,
				Expected: triageguard.ExpectedEvidence{Present: &present, Value: &payload}, Observed: triageguard.Observation{State: triageguard.ObservationPresent, Value: &payload}, Status: triageguard.StatusUnchanged, Reason: triageguard.ReasonMatch}}}}}
	var output bytes.Buffer
	if err := triageguard.WriteMarkdown(&output, report); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Count(text, "\n## ") != 1 || strings.Contains(text, "<script>") || strings.Contains(text, "[link](") || strings.Contains(text, "\r") {
		t.Fatalf("supplied text created Markdown structure:\n%s", text)
	}
	rationaleSeen, rowSeen := false, false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Original reasoning: ") {
			rationaleSeen = true
			var decoded string
			if err := json.Unmarshal([]byte(html.UnescapeString(strings.TrimPrefix(line, "Original reasoning: "))), &decoded); err != nil || decoded != payload {
				t.Fatalf("rationale did not retain original text: %v", err)
			}
		}
		if strings.HasPrefix(line, "| &#34;") {
			rowSeen = true
			cells := strings.Split(line, "|")
			if len(cells) != 10 {
				t.Fatalf("injected table cells: %d", len(cells))
			}
			for _, index := range []int{1, 3, 4} {
				var decoded string
				if err := json.Unmarshal([]byte(html.UnescapeString(strings.TrimSpace(cells[index]))), &decoded); err != nil || decoded != payload {
					t.Fatalf("table field %d lost its text: %v", index, err)
				}
			}
			var expected triageguard.ExpectedEvidence
			if err := json.Unmarshal([]byte(html.UnescapeString(strings.TrimSpace(cells[5]))), &expected); err != nil || expected.Value == nil || *expected.Value != payload {
				t.Fatalf("expected evidence text lost: %v", err)
			}
			var observed triageguard.Observation
			if err := json.Unmarshal([]byte(html.UnescapeString(strings.TrimSpace(cells[6]))), &observed); err != nil || observed.Value == nil || *observed.Value != payload {
				t.Fatalf("observed evidence text lost: %v", err)
			}
		}
	}
	if !rationaleSeen || !rowSeen {
		t.Fatal("rationale or assumption evidence was dropped")
	}
}

func TestWriteMarkdownWhitespaceDisplay(t *testing.T) {
	for _, test := range []struct {
		name               string
		expected, observed string
		wantExpected       string
		wantObserved       string
	}{
		{"ordinary-sentence", "A human decision.", "Another decision.", `A human decision.`, `Another decision.`},
		{"quoted-words", `A "human" decision`, `A "reviewed" decision`, `A \"human\" decision`, `A \"reviewed\" decision`},
		{"repeated", "a  b", "a b", `a\u0020\u0020b`, `a b`},
		{"leading", " a", "a", `\u0020a`, `a`},
		{"trailing", "a ", "a", `a\u0020`, `a`},
		{"space-only", "  ", " ", `\u0020\u0020`, `\u0020`},
		{"literal-escape", " ", `\u0020`, `\u0020`, `\\u0020`},
	} {
		t.Run(test.name, func(t *testing.T) {
			present := true
			report := triageguard.Report{SchemaVersion: 1,
				Decisions: []triageguard.DecisionResult{{ID: "display", Assumptions: []triageguard.AssumptionResult{{
					ID: "value", Kind: triageguard.KindConfig, Key: &test.expected,
					Expected: triageguard.ExpectedEvidence{Present: &present, Value: &test.expected},
					Observed: triageguard.Observation{State: triageguard.ObservationPresent, Value: &test.observed},
				}}}}}
			var output bytes.Buffer
			if err := triageguard.WriteMarkdown(&output, report); err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(output.String(), "\n") {
				if !strings.HasPrefix(line, "| &#34;") {
					continue
				}
				cells := strings.Split(line, "|")
				expectedText := html.UnescapeString(strings.TrimSpace(cells[5]))
				observedText := html.UnescapeString(strings.TrimSpace(cells[6]))
				if !strings.Contains(expectedText, `"value":"`+test.wantExpected+`"`) || !strings.Contains(observedText, `"value":"`+test.wantObserved+`"`) {
					t.Fatalf("displayed evidence lost whitespace distinction: expected %s; observed %s", expectedText, observedText)
				}
				// Normal HTML whitespace collapsing must not hide a difference.
				// Single internal spaces stay readable; other spaces are escaped.
				for _, displayed := range []string{expectedText, observedText} {
					if strings.Join(strings.Fields(displayed), " ") != displayed {
						t.Fatalf("display contains collapsible whitespace: %q", displayed)
					}
				}
				var expected triageguard.ExpectedEvidence
				var observed triageguard.Observation
				if err := json.Unmarshal([]byte(expectedText), &expected); err != nil || expected.Value == nil || *expected.Value != test.expected {
					t.Fatalf("expected value no longer round-trips: %v", err)
				}
				if err := json.Unmarshal([]byte(observedText), &observed); err != nil || observed.Value == nil || *observed.Value != test.observed {
					t.Fatalf("observed value no longer round-trips: %v", err)
				}
				return
			}
			t.Fatal("assumption evidence row is missing")
		})
	}
}

type renderFailWriter struct {
	err   error
	short bool
}

func (w renderFailWriter) Write(data []byte) (int, error) {
	if w.short {
		return len(data) - 1, w.err
	}
	return 0, w.err
}

func TestWriteReportWriterErrors(t *testing.T) {
	report := renderFixtures(t)["mixed"]
	sentinel := errors.New("destination failed")
	for format, write := range renderWriters() {
		for _, test := range []struct {
			name   string
			writer renderFailWriter
			want   error
		}{{"failed", renderFailWriter{err: sentinel}, sentinel}, {"partial-failed", renderFailWriter{err: sentinel, short: true}, sentinel}, {"short", renderFailWriter{short: true}, io.ErrShortWrite}} {
			t.Run(format+"/"+test.name, func(t *testing.T) {
				if err := write(test.writer, report); !errors.Is(err, test.want) {
					t.Fatalf("writer error = %v, want %v", err, test.want)
				}
			})
		}
	}
}

func TestWriteReportUsesOnlySuppliedWriter(t *testing.T) {
	stdout, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	originalOut, originalErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	defer func() { os.Stdout, os.Stderr = originalOut, originalErr }()
	for _, write := range renderWriters() {
		if err := write(io.Discard, renderFixtures(t)["mixed"]); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []*os.File{stdout, stderr} {
		info, err := file.Stat()
		if err != nil || info.Size() != 0 {
			t.Fatalf("unexpected process stream output: %v", err)
		}
	}
}
