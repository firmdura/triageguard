# Version 1 schema and behavior reference

This reference defines the manifest format, evidence formats, and result rules
for version 1. TriageGuard checks the assumptions recorded in a previous human
CVE review. An `unchanged` result means those assumptions still match; it does
not establish CVE applicability, remediation, security, or compliance. Reports
can contain configuration values and the reasoning behind a decision. Review
them before sharing.

The Go module is `github.com/firmdura/triageguard` and uses the
[Apache-2.0 license](../LICENSE). Its only direct dependency is
`go.yaml.in/yaml/v3 v3.0.4`, whose upstream license is included in the
distribution. The project's original test fixtures are synthetic and contain
no customer data.

## Toolchain and package structure

The project selected Go **1.27.4** from [go.dev/dl](https://go.dev/dl/) on
November 15, 2026. In `go.mod`,
`toolchain go1.27.4` names the preferred toolchain, and `go 1.27.0` sets the
minimum Go version. Verification requires Go 1.27.4 on Linux and uses
`GOTOOLCHAIN=local` to disable automatic toolchain downloads. The `toolchain`
directive alone does not enforce an exact version: Go can use a newer installed
toolchain.

The shared types, constants, validation rules, and `Collector` interface live in
`internal/contracts`. The public package exposes aliases for those types and
constants in `pkg/triageguard/types.go`. Internal packages import
`internal/contracts`; they must not import the public `pkg/triageguard` package.
The public package calls the internal implementations. The CLI connects
`LoadManifest`, `Check`, `WriteJSON`, and `WriteMarkdown` through adapters in
`internal/cli`, so the CLI and library use the same validation and result rules.

## Manifest YAML

`LoadManifest(io.Reader) (Manifest, error)` accepts one YAML document whose root
is a mapping. The document can be at most **1 MiB (1,048,576 bytes)**. On any
error, the function returns a zero-value manifest.

The loader rejects unknown fields, duplicate mapping keys, keys that are not
strings, YAML aliases (including merge aliases), unsupported schema versions,
incorrect value types, null required values, and multiple documents. An unused
YAML anchor is allowed. Boolean and numeric values are not converted to strings.

```yaml
schema_version: 1
decisions:
  - id: illustrative-decision
    cve: CVE-2024-0001
    baseline: release-1
    rationale: A synthetic human decision, not an affected-product claim.
    assumptions:
      - id: feature-disabled
        kind: config
        path: build-config.json
        key: FEATURE_X
        expected_present: true
        expected_value: 'n'
      - id: file-retained
        kind: file
        path: src/parser.c
        expected_sha256: '0000000000000000000000000000000000000000000000000000000000000000'
      - id: inventory-entry
        kind: patch
        path: patches.json
        key: fix-1
        expected_present: false
```

The all-zero hash above is a syntax example. Replace it with the actual file's
SHA-256 before using the manifest.

The root must contain `schema_version: 1` and at least one decision. Each
decision has exactly these fields: `id`, `cve`, `baseline`, `rationale`, and
`assumptions`. The ID, baseline, and rationale must each contain at least one
character other than whitespace. The CVE must match
`^CVE-[0-9]{4}-[0-9]{4,}$`. Every decision must have at least one assumption.
Decision IDs must be unique, and assumption IDs must be unique across the
entire manifest. A duplicate-ID error identifies both entries. For decision
IDs it gives their positions in the manifest; for assumption IDs it gives
each decision's ID and the position within that decision's assumption list.
Positions start at 1.

Every assumption needs a nonblank `id`, a supported `kind`, and a nonempty
string `path`. Its remaining fields depend on what it checks:

| Kind and expectation | Required fields | Forbidden fields |
| --- | --- | --- |
| config, present | `key`, `expected_present: true`, string `expected_value` | `expected_sha256` |
| config, absent | `key`, `expected_present: false` | `expected_value`, `expected_sha256` |
| file | `expected_sha256` | `key`, `expected_present`, `expected_value` |
| patch, present | `key`, `expected_present: true`, `expected_sha256` | `expected_value` |
| patch, absent | `key`, `expected_present: false` | `expected_value`, `expected_sha256` |

SHA-256 strings must contain exactly 64 lowercase hexadecimal digits. The `key`
field must be supplied as a string; an empty string is allowed as a JSON object
key. An expected empty config value (`expected_value: ''`) means the key must
exist with an empty string value. It is different from expecting the key to be
absent. Forbidden fields are rejected even when their value is null.

Evidence paths are relative to the evidence root and use `/` as the separator.
They must not contain empty, `.` or `..` components, backslashes, NUL characters,
or symbolic links, and must not be absolute. Paths are checked as supplied;
TriageGuard does not normalize them.

The manifest loader keeps nonempty unsafe paths in the manifest. The collector
then reports the affected assumption as `unverifiable` with reason `unsafe-path`,
without losing results for other assumptions. On Linux, it opens each path
component relative to an already-open directory handle and refuses symbolic
links, avoiding a separate path check followed by an unprotected open. Only
regular files are read. No other process should change the inputs during a
check; these protections do not guarantee a snapshot of a filesystem under
deliberate concurrent modification.

In Go code, use `Assumption{ID, Path, Expectation}` and set `Expectation` to a
pointer to `ConfigPresent`, `ConfigAbsent`, `FileSHA256`, `PatchPresent`, or
`PatchAbsent`. Absence types have no value or hash field. Nil interfaces and
typed nil pointers are invalid.

`Check` calls `ValidateManifest` from `internal/contracts` before opening the
evidence root, applying the same structural rules to manifests created in Go.
`Assumption.MarshalYAML` writes the flat YAML format shown above, so a valid
manifest can be written to YAML and read back with `LoadManifest`. Do not modify
a manifest or report while a function is using it. Always use `LoadManifest`
when reading YAML; a general-purpose decoder does not perform the same checks.

## Evidence exports and collection

An exported config file contains one JSON object with string values, such as
`{"FEATURE_X":"n","EMPTY":""}`. An exported patch inventory contains one
JSON object mapping patch IDs to lowercase SHA-256 strings.

Duplicate keys, non-string values, trailing JSON data, invalid UTF-8, unpaired
Unicode surrogates, or a malformed patch hash anywhere in the object make the
entire export unavailable. Valid extra entries do not affect checks of other
keys. Each JSON export can be at most **16 MiB (16,777,216 bytes)**, and each
regular file being hashed can be at most **1 GiB (1,073,741,824 bytes)**. Exceeding
a limit produces an unavailable observation, never a match.

The internal collector uses this interface:

```go
type Collector interface {
    Observe(context.Context, Assumption) (Observation, error)
}
```

The concrete collector opens and validates the root directory when it is
created, then closes the directory handle in `Close`. The `Collector` interface
itself only describes observation; it does not manage that setup or cleanup.
Collectors do not compare expected values or assign result statuses. They
return one of these observations:

| Observation state | Payload | Meaning |
| --- | --- | --- |
| `present` | Nonnil `Value` for config or `SHA256` for file/patch; no `Reason` | The file or key was read successfully and is present |
| `absent` | No value, hash, or reason | The config or patch key is absent from a valid, readable export |
| `unavailable` | No value or hash; one failure reason | The evidence could not be read or trusted |

A missing file is always `unavailable`; `absent` is reserved for a missing key
in a valid export. A config value can be an empty string. Observations contain
no raw operating-system errors or absolute paths.

The collector returns an error only when the context is canceled or its deadline
expires, aborting the check. Other evidence failures stay in the report. While
hashing, the collector checks for cancellation, reads through one open file
handle, and reports `evidence-changed` if it detects a change in file size or
modification time. No component writes to inputs, runs builds or scanners, or
makes network requests.

## Comparison and report boundary

Evaluation keeps every assumption and sorts decisions and assumptions by ID.
A matching config value, file hash, or hash recorded for a patch ID produces
`unchanged` with reason `match`. A key that is absent as expected produces the same result.
Other comparisons produce:

| Comparison | Status | Reason |
| --- | --- | --- |
| Config value differs | `review-required` | `value-changed` |
| File hash or hash recorded for a patch ID differs | `review-required` | `hash-changed` |
| Expected key is missing from a valid map | `review-required` | `key-missing` |
| Key expected to be absent is present | `review-required` | `key-unexpected` |
| Any unavailable observation | `unverifiable` | The observation's evidence failure code |

A missing patch ID requires review when `expected_present: true` and matches
when `expected_present: false`. Either result describes only the inventory; it
does not prove whether the patch is present in the firmware.

Unavailable evidence uses these reason codes:

| Code | Meaning |
| --- | --- |
| `evidence-missing` | The evidence file does not exist |
| `evidence-unreadable` | Permission denied, or another failure to open, read, or inspect the file |
| `invalid-export` | The config or patch JSON export is invalid |
| `unsafe-path` | Forbidden path syntax or a symbolic link in the path |
| `unsupported-file-kind` | Evidence is not a regular file, or an intermediate path component is not a directory |
| `limit-exceeded` | The export or file exceeds its size limit |
| `evidence-changed` | File size or modification time changed during the read |

For both decisions and the overall report, unavailable evidence takes
precedence over a changed assumption. Changed assumptions take precedence over
matches:

| Status | Reason | When it applies |
| --- | --- | --- |
| `unverifiable` | `evidence-unavailable` | At least one assumption could not be checked |
| `review-required` | `assumptions-changed` | At least one assumption changed and all evidence was available |
| `unchanged` | `all-unchanged` | Every assumption matched |

All observations remain visible, including changes alongside unavailable
evidence. None of these results says that a vulnerability is fixed, that a
product is unaffected, or that a compliance requirement has been met.

`Report` has `schema_version`, overall `status` and `reason`, `summary`, and
`decisions`. Both `summary.decisions` and `summary.assumptions` count
`unchanged`, `review_required`, and `unverifiable` results. Each decision contains
`id`, `cve`, `baseline`, `rationale`, `status`, `reason`, and `assumptions`.
Each assumption contains `id`, `kind`, the manifest's `path`, optional `key`,
`expected`, `observed`, `status`, and `reason`.

`expected.present` is always a nonnil boolean; for files, it is true.
`expected.value` appears only when a config key is expected to be present.
`expected.sha256` appears only for files or patch IDs expected to be present.
`observed` follows the observation table above. Optional value and key pointers
ensure that empty strings remain explicit in JSON.

Reports omit timestamps, machine-specific absolute root paths, environment
dumps, and raw operating-system diagnostics. The writers sort copies of the
results, preserve the supplied fields and statuses, escape Markdown text, and
return output errors. Markdown adds plain-English explanations beside the exact
reason codes. Supplied strings use JSON quoting, with ordinary single spaces
left readable and leading, trailing, or repeated ASCII spaces shown as `\u0020`.
Markdown also escapes non-ASCII whitespace. Neither writer collects or evaluates
evidence.

## Public check and command

`Check(context.Context, Manifest, root string) (Report, error)` validates the
manifest, opens the evidence root on Linux, checks every assumption, and closes
the root handle before returning. Changed assumptions and unavailable evidence
produce a complete report with a nil error. Invalid manifests, failures to open
or close the root, nil contexts, and cancellation or deadline expiration produce
a zero-value report and an error. Cancellation errors support `errors.Is` for
`context.Canceled` and `context.DeadlineExceeded`. The library never exits the
process, writes to inputs, or makes network requests.

```sh
go build -o bin/triageguard ./cmd/triageguard
bin/triageguard check --manifest decisions.yaml --root ./evidence --format json
bin/triageguard --help
bin/triageguard --version
```

The CLI requires `--manifest` and `--root`. The `--format` option defaults to
`json` and also accepts `markdown`. Options accept `--name value` or
`--name=value`. Unknown or duplicate options, extra positional arguments, missing
or empty values, and unsupported formats are usage errors. The manifest must
be a regular file; named pipes and devices are rejected without a blocking
read. `--help` (or `-h`) works alone at the top level or after `check`.
`--version` works alone at the top level. Help and version commands exit 0 when
writing their output succeeds. Development builds show `triageguard dev`;
release builds set the version with `-ldflags '-X main.version=v1.0.0'`.

For `check`, standard output (stdout) contains only the chosen report;
diagnostic messages go to standard error (stderr). Exit 0 means every assumption
is unchanged. Exit 1 means at least one requires review and none are
unverifiable. Exit 2 means invalid input, an I/O failure, cancellation, or at
least one unverifiable assumption. Setup, validation, and cancellation failures
produce no report. SIGINT and SIGTERM cancel evaluation. A broken output pipe
returns 2; discard any partial report after a write failure.

## Manifest and integration tests

The valid fixture and invalid-input fixtures are in
[`testdata/contracts`](../testdata/contracts). Tests also check the exact 1 MiB
boundary and an oversized synthetic reader, without committing a large file.
To run the focused checks:

```sh
go test ./pkg/triageguard -run 'TestManifest|TestContract' -count=1
go test ./internal/contracts -count=1
go vet ./pkg/triageguard
go list -deps ./...
```

The external alias test creates a temporary Go module that imports only
`pkg/triageguard`. It runs with `GOPROXY=off` and `GOSUMDB=off`, using dependencies
that have already been downloaded.

On Linux, `go test ./internal/cli -run TestCLI -count=1` builds and runs both the
CLI and a consumer of the public Go package. It compares their reports for
matching assumptions, changed assumptions, unavailable evidence, and invalid
evidence. It also checks exit codes, invalid arguments, invalid manifests and
roots, unchanged input hashes, repeatable output, broken pipes, nonregular
manifest files, and signal cancellation during a real file hash. Prepare
dependencies before running these tests offline. Run the full suite in the
pinned Linux environment.
