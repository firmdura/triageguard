package triageguard

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// WriteJSON writes a deterministic, indented JSON report followed by a newline.
// It sorts copies of decisions and assumptions by ID without changing report,
// collecting evidence, or recomputing any supplied verdict or count. Callers
// must not mutate report concurrently. Writer errors are returned to the caller.
func WriteJSON(w io.Writer, report Report) error {
	data, err := json.MarshalIndent(orderedReport(report), "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	return writeReport(w, append(data, '\n'))
}

// WriteMarkdown writes a deterministic Markdown report, sorting copies of
// decisions and assumptions by ID. Strings are displayed as escaped JSON
// literals so empty strings, whitespace, and absent optional fields remain
// distinct and supplied text cannot create Markdown structure. Ordinary spaces
// remain readable; leading, trailing, and repeated spaces are visibly escaped.
// Expected and observed evidence retain their JSON field names. The writer does
// not collect evidence or recompute verdicts or counts. Writer errors are returned
// to the caller.
func WriteMarkdown(w io.Writer, report Report) error {
	report = orderedReport(report)
	var out strings.Builder
	out.WriteString("# TriageGuard evidence report\n\n")
	out.WriteString("This report compares the assumptions recorded in previous CVE assessments with the available evidence.\n\n")
	out.WriteString("An `unchanged` result means only that the recorded assumptions still match. It does not tell you whether a CVE affects a product, whether a fix works, or whether the product is secure or compliant.\n\n")
	fmt.Fprintf(&out, "Schema version: %d\n\nOverall status: %s\n\nReason: %s\n\n", report.SchemaVersion, markdownJSON(report.Status), markdownReason(report.Reason))
	out.WriteString("| Result counts | Unchanged | Review required | Unverifiable |\n| --- | ---: | ---: | ---: |\n")
	writeCounts(&out, "Decisions", report.Summary.Decisions)
	writeCounts(&out, "Assumptions", report.Summary.Assumptions)
	out.WriteString("\nHow to read the status codes:\n\n")
	out.WriteString("- `unchanged`: The recorded assumptions still match.\n")
	out.WriteString("- `review-required`: At least one assumption changed, and all evidence was available. Have a human reviewer reassess the original decision.\n")
	out.WriteString("- `unverifiable`: At least one assumption could not be checked. Restore or correct the evidence and run the check again. Any other changes remain visible in the report.\n\n")
	out.WriteString("A baseline identifies the version or build originally reviewed. The original reasoning records why that decision was made. Review this report before sharing it: it can contain sensitive reasoning, configuration values, paths, and hashes.\n\n")
	out.WriteString("The evidence cells retain the exact recorded fields. `present` says whether a file or key is expected to exist. `state` describes what was found: `present`, `absent` for a missing key in a valid export, or `unavailable` when the evidence could not be checked. `value` is a configuration string, and `sha256` is a file hash or the hash recorded for a patch ID.\n\n")
	out.WriteString("Quoted text preserves the supplied values. Ordinary spaces remain readable; leading, trailing, or repeated spaces appear as `\\u0020`. Escaped tabs and line breaks also belong to the original text. An empty string is shown as `\"\"`. In the Key column, (not supplied) means the assumption has no key field; it is different from a key missing from an evidence export.\n")
	for _, decision := range report.Decisions {
		fmt.Fprintf(&out, "\n## Decision %s\n\n", markdownJSON(decision.ID))
		fmt.Fprintf(&out, "CVE: %s\n\nReviewed baseline: %s\n\nOriginal reasoning: %s\n\nStatus: %s\n\nReason: %s\n\n",
			markdownJSON(decision.CVE), markdownJSON(decision.Baseline), markdownJSON(decision.Rationale), markdownJSON(decision.Status), markdownReason(decision.Reason))
		out.WriteString("| Assumption | Evidence type | Evidence path | Key | Recorded expectation | Evidence found | Status | Reason |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, assumption := range decision.Assumptions {
			key := "(not supplied)"
			if assumption.Key != nil {
				key = markdownJSON(*assumption.Key)
			}
			fmt.Fprintf(&out, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				markdownJSON(assumption.ID), markdownJSON(assumption.Kind), markdownJSON(assumption.Path), key,
				markdownJSON(assumption.Expected), markdownJSON(assumption.Observed), markdownJSON(assumption.Status), markdownReason(assumption.Reason))
		}
	}
	return writeReport(w, []byte(out.String()))
}

func orderedReport(report Report) Report {
	if report.Decisions == nil {
		return report
	}
	report.Decisions = append([]DecisionResult{}, report.Decisions...)
	for i := range report.Decisions {
		if report.Decisions[i].Assumptions != nil {
			report.Decisions[i].Assumptions = append([]AssumptionResult{}, report.Decisions[i].Assumptions...)
			sort.Slice(report.Decisions[i].Assumptions, func(a, b int) bool {
				return report.Decisions[i].Assumptions[a].ID < report.Decisions[i].Assumptions[b].ID
			})
		}
	}
	sort.Slice(report.Decisions, func(a, b int) bool { return report.Decisions[a].ID < report.Decisions[b].ID })
	return report
}

func writeCounts(out *strings.Builder, label string, counts Counts) {
	fmt.Fprintf(out, "| %s | %d | %d | %d |\n", label, counts.Unchanged, counts.ReviewRequired, counts.Unverifiable)
}

func markdownReason(reason ReasonCode) string {
	var explanation string
	switch reason {
	case ReasonAllUnchanged:
		explanation = "All recorded assumptions match."
	case ReasonAssumptionsChanged:
		explanation = "At least one recorded assumption changed."
	case ReasonEvidenceUnavailable:
		explanation = "At least one assumption could not be checked."
	case ReasonMatch:
		explanation = "The evidence matches the recorded expectation."
	case ReasonValueChanged:
		explanation = "The configuration value changed."
	case ReasonHashChanged:
		explanation = "The file hash or the hash recorded for the patch ID changed."
	case ReasonKeyMissing:
		explanation = "A key expected to be present is missing."
	case ReasonKeyUnexpected:
		explanation = "A key expected to be absent is present."
	case ReasonEvidenceMissing:
		explanation = "The evidence file is missing."
	case ReasonEvidenceUnreadable:
		explanation = "The evidence file could not be opened, read, or inspected."
	case ReasonInvalidExport:
		explanation = "The configuration or patch inventory export is invalid."
	case ReasonUnsafePath:
		explanation = "The evidence path uses forbidden syntax or contains a symbolic link."
	case ReasonUnsupportedFileKind:
		explanation = "The evidence is not a regular file, or part of the path is not a directory."
	case ReasonLimitExceeded:
		explanation = "The evidence exceeds its size limit."
	case ReasonEvidenceChanged:
		explanation = "The file's size or modification time changed while it was read."
	}
	code := markdownJSON(reason)
	if explanation == "" {
		return code
	}
	return explanation + " (" + code + ")"
}

func markdownJSON(value any) string {
	// All callers supply strings or the concrete, JSON-encodable evidence types.
	data, _ := json.Marshal(value)
	var escaped strings.Builder
	inString, inEscape, stringStart := false, false, -1
	for i, r := range string(data) {
		if inEscape {
			inEscape = false
		} else if r == '\\' && inString {
			inEscape = true
		} else if r == '"' {
			inString = !inString
			if inString {
				stringStart = i + 1
			}
		}
		// A single internal space survives normal HTML whitespace collapsing.
		// Make boundary and repeated spaces visible so no significant whitespace
		// can disappear, while ordinary sentences remain readable.
		if r == ' ' && (i == stringStart || data[i-1] == ' ' || data[i+1] == ' ' || data[i+1] == '"') {
			escaped.WriteString("&#92;u0020")
			continue
		}
		// Character references are parsed as text rather than Markdown syntax.
		// Encoding every ASCII punctuation character also covers table pipes,
		// backticks, HTML delimiters, links, and literal entity-like input.
		if r >= '!' && r <= '/' || r >= ':' && r <= '@' || r >= '[' && r <= '`' || r >= '{' && r <= '~' {
			escaped.WriteString("&#")
			escaped.WriteString(strconv.Itoa(int(r)))
			escaped.WriteByte(';')
		} else {
			escaped.WriteRune(r)
		}
	}
	return escaped.String()
}

func writeReport(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
