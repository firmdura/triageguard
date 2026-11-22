# Go API

Use this package to load a decision manifest, check its evidence, and write a
report from your own Go program:

```go
import "github.com/firmdura/triageguard/pkg/triageguard"
```

The module path is `github.com/firmdura/triageguard`. Checking evidence requires
Linux; the project uses Go 1.27.4 for builds and verification. The public package
provides the types and constants you need, so you do not need to import any
`internal` packages. See the [build instructions](../README.md) and
[version 1 schema reference](contracts.md).

The source and released module are public. From your application's Go module,
download the released dependency while network access is available:

```sh
GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  go get github.com/firmdura/triageguard/pkg/triageguard@v1.0.1
```

Browse the [v1.0.1 package documentation](https://pkg.go.dev/github.com/firmdura/triageguard@v1.0.1/pkg/triageguard).
The repository's library smoke test works differently: it uses a local `replace`
directive to test the code in your checkout offline. It does not download the
released module.

## Functions and errors

```go
func LoadManifest(r io.Reader) (Manifest, error)
func Check(ctx context.Context, manifest Manifest, root string) (Report, error)
func WriteJSON(w io.Writer, report Report) error
func WriteMarkdown(w io.Writer, report Report) error
```

`LoadManifest` reads one YAML document with `schema_version: 1`, up to
`MaxManifestBytes` (1 MiB). It rejects unknown or duplicate fields, YAML aliases,
duplicate decision or assumption IDs, incorrect value types, and invalid
combinations of expectation fields. If validation fails, it returns a zero-value
`Manifest` and an error. It does not open evidence files. Always use this function
to load manifests; a general-purpose YAML decoder does not perform the same
validation. If you pass an open file, you are responsible for closing it.

`Check` also validates manifests created in Go code. It opens the evidence
directory, checks every assumption, and closes its directory handle before
returning. Changed assumptions and unavailable evidence both produce a complete
`Report` with a nil error. **Always inspect `Report.Status`, even when the error
is nil.**

An invalid manifest, a failure to open or close the evidence directory, a nil
context, or cancellation or deadline expiration produces a zero-value report
and an error. Cancellation errors support
`errors.Is(err, context.Canceled)` and
`errors.Is(err, context.DeadlineExceeded)`. Handle the error before using the
report. The evidence root must be an existing directory on Linux. The final
component of the root path cannot be a symbolic link.

`WriteJSON` and `WriteMarkdown` sort copies of the decisions and assumptions by
ID, leaving the supplied report untouched. They display the results and counts
already in the report; they do not read evidence or recalculate the result.
`WriteJSON` writes indented JSON followed by a newline. `WriteMarkdown` explains
the status and reason codes in plain English and displays exact evidence in
quoted JSON form. Ordinary single spaces remain readable; leading, trailing,
and repeated ASCII spaces use visible `\u0020` escapes. Non-ASCII whitespace
is escaped too (for example, `\u00a0` for a nonbreaking space). Both functions
return output errors, including short writes. If writing fails, discard any
partial output.

The library does not call `os.Exit`, modify inputs, run builds or scanners, or
make network requests. Your application decides how to exit. The CLI uses
0 for `StatusUnchanged`, 1 for `StatusReviewRequired`, and 2 for
`StatusUnverifiable` or a returned error/output failure.

## Complete file-based example

This program takes a manifest path and an evidence directory. It allows up to
30 seconds for the check, writes a JSON report, and returns the same exit codes
as the CLI. The repository's example manifest uses synthetic evidence. A match
does not establish CVE applicability, remediation, security, or compliance.

```go
package main

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/firmdura/triageguard/pkg/triageguard"
)

func main() { os.Exit(run()) }

func run() int {
    if len(os.Args) != 3 {
        fmt.Fprintln(os.Stderr, "usage: api-check MANIFEST EVIDENCE_ROOT")
        return 2
    }
    fail := func(err error) int {
        fmt.Fprintln(os.Stderr, err)
        return 2
    }
    file, err := os.Open(os.Args[1])
    if err != nil {
        return fail(err)
    }
    manifest, loadErr := triageguard.LoadManifest(file)
    closeErr := file.Close()
    if loadErr != nil {
        return fail(loadErr)
    }
    if closeErr != nil {
        return fail(closeErr)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    report, err := triageguard.Check(ctx, manifest, os.Args[2])
    if err != nil {
        return fail(err)
    }
    // For Markdown output, call triageguard.WriteMarkdown instead.
    if err := triageguard.WriteJSON(os.Stdout, report); err != nil {
        return fail(err)
    }
    switch report.Status {
    case triageguard.StatusUnchanged:
        return 0
    case triageguard.StatusReviewRequired:
        return 1
    default:
        return 2
    }
}
```

The [runnable example](../examples/go-check/main.go) also lets you choose JSON
or Markdown output. To test it from a Linux checkout after preparing
dependencies, run:

```sh
./scripts/test-library.sh
```

The script creates a temporary Go module that imports the public package from
your checkout through a local `replace` directive. It tests matching assumptions,
changed assumptions, and unavailable evidence in both output formats, comparing
the results with the CLI and the checked-in expected reports. Downloads of
modules and toolchains are disabled, and the test fixtures are left unchanged.
See the [walkthrough](tutorial.md) for dependency preparation and input files.

## Programmatic expectations

An `Assumption` contains an `ID`, a `Path`, and one `Expectation`. Set
`Expectation` to a nonnil pointer to one of the supported types below. The two
`ConfigPresent` examples show the difference between a nonempty and an empty
string.

| Expectation | Meaning |
| --- | --- |
| `&ConfigPresent{Key: "FEATURE_X", Value: "n"}` | Key must exist with that exact string |
| `&ConfigPresent{Key: "EMPTY", Value: ""}` | Key must exist with an explicitly empty string |
| `&ConfigAbsent{Key: "NOT_EXPORTED"}` | Key must be absent from a valid readable config export |
| `&FileSHA256{SHA256: digest}` | Regular file must have the given lowercase SHA-256 |
| `&PatchPresent{Key: "fix-id", SHA256: digest}` | Inventory ID must exist with that digest |
| `&PatchAbsent{Key: "fix-id"}` | ID must be absent from a valid readable inventory |

Here is a complete minimal programmatic manifest for a config export containing
`{"FEATURE_X":"n","EMPTY":""}`:

```go
manifest := triageguard.Manifest{
    SchemaVersion: triageguard.SchemaVersion,
    Decisions: []triageguard.Decision{{
        ID: "synthetic-review",
        CVE: "CVE-2024-0001",
        Baseline: "synthetic-release-1",
        Rationale: "Synthetic review assumed the feature was disabled.",
        Assumptions: []triageguard.Assumption{
            {ID: "feature-disabled", Path: "build-config.json",
                Expectation: &triageguard.ConfigPresent{Key: "FEATURE_X", Value: "n"}},
            {ID: "empty-present", Path: "build-config.json",
                Expectation: &triageguard.ConfigPresent{Key: "EMPTY", Value: ""}},
            {ID: "key-absent", Path: "build-config.json",
                Expectation: &triageguard.ConfigAbsent{Key: "NOT_EXPORTED"}},
        },
    }},
}
report, err := triageguard.Check(context.Background(), manifest, evidenceRoot)
```

Manifests created in Go must follow the same rules for required strings, unique
assumption IDs, CVE syntax, and hashes as YAML manifests. A nil `Expectation`
interface or a typed nil pointer is invalid. A nonempty but unsafe evidence path
produces a `StatusUnverifiable` result with `ReasonUnsafePath`, so that assumption
remains visible in the report.

`ConfigExport` and `PatchExport` represent the JSON export maps. When reading
evidence, TriageGuard rejects duplicate keys and invalid values instead of
silently accepting them. A missing patch ID tells you only about the exported
inventory; it does not prove that a patch is absent from the firmware.

## Report models and caller responsibilities

`Report` contains the schema version, overall status and reason, summary counts,
and every `DecisionResult`. Each decision includes its ID, CVE, baseline,
rationale, status, reason, and all of its `AssumptionResult` values. Each
assumption includes its kind, relative path, optional key, expected evidence,
observed evidence, status, and reason.

Presence fields and optional value or hash pointers distinguish an absent key
from an empty string. A present config observation has a `Value`; a present file
or patch observation has a `SHA256`. An absent observation has neither value nor
hash. An unavailable observation also has neither, but includes a failure
`Reason`.
`Summary.Decisions` and `Summary.Assumptions` each contain `Counts` for unchanged,
review-required and unverifiable results. All statuses and reasons are listed in
the [v1 contracts](contracts.md#comparison-and-report-boundary).

The overall status is `StatusUnverifiable` if any evidence is unavailable.
Otherwise, it is `StatusReviewRequired` if any assumption changed, or
`StatusUnchanged` if all assumptions match. Every observation remains in the
report. Decisions and assumptions are sorted by ID. Reports omit timestamps,
absolute root paths, and environment dumps, so repeated checks of the same
unchanged inputs produce byte-for-byte identical output.

Keep the evidence read-only, and make sure no other process changes it during a
check. Do not modify a manifest or report while a library function is using it.
Separate calls can use separate inputs that remain unchanged during use.
TriageGuard detects changes in file size or modification time while reading,
but cannot guarantee a consistent snapshot if another process deliberately
changes files and restores their metadata. The limits are
`MaxManifestBytes` (1 MiB), `MaxExportBytes` (16 MiB per JSON export), and
`MaxFileBytes` (1 GiB per file hash). Exceeding a limit produces an error or an
unverifiable result, never an unchanged result.

Reports contain configuration values, paths, hashes, and the reasoning behind
the original decision. Review them before sharing and store them with the
historical decision where only the intended readers can access them. Changed
assumptions require a new human review. The API does not rewrite decisions,
create VEX records, or determine whether a vulnerability applies. See
[usage](usage.md) for reassessment and CI handling.
