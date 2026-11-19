# TriageGuard v1.0.0 design

This document describes the scope, behavior, and verification requirements of
TriageGuard v1.0.0. For installation and current usage, start with the
[README](../README.md).

## Intended outcome

Deliver a local Go command-line tool and library that recheck the assumptions
behind a previous human CVE decision. An `unchanged` result means those
assumptions still match. It does not mean that the CVE is harmless. Historical
decisions remain intact, and changed assumptions call for a new human review.

## Scope

The release includes:

- A versioned YAML manifest containing decision IDs, CVE IDs, the reasoning
  behind each decision, a baseline identifier, and the assumptions to check.
- Three kinds of evidence: exact string values in an exported JSON config map,
  the SHA-256 hash of a regular file, and the presence or hash of a patch ID in
  an exported JSON inventory.
- Read-only checks within a supplied evidence directory, repeatable JSON and
  Markdown reports, documented CLI exit codes, and a reusable
  `pkg/triageguard` API.
- An `unchanged`, `review-required`, or `unverifiable` result for each assumption
  and decision, with stable reason codes.
- Synthetic examples and tests that need no customer repository or private files.

The release does not determine CVE applicability or code reachability. It does
not use vulnerability feeds or scanners, run builds, parse BitBake or Buildroot
configuration, ingest SBOMs, create or rewrite VEX records, apply fixes, or edit
source files. It includes no server, user interface, or approval workflow, and
makes no claim of compliance or security certification. Engineers export config
values and patch inventories into the documented JSON formats before checking.

## Manifest and evidence rules

The CLI accepts a manifest, an evidence directory, and a report format:

```sh
triageguard check --manifest decisions.yaml --root ./evidence --format json
```

The format can be `json` or `markdown`. Reports go to standard output, and
diagnostic messages go to standard error. Exit 0 means all assumptions match.
Exit 1 means at least one assumption changed and all evidence was available.
Exit 2 means invalid input, an I/O failure, or at least one assumption that could
not be checked. Invalid manifests produce no report, and output failures return
2. The help and version commands return 0 when their output succeeds.

Manifests use `schema_version: 1`. Unknown fields, duplicate YAML keys, duplicate
decision or assumption IDs, YAML aliases, malformed SHA-256 hashes, and
unsupported versions are rejected. Each decision needs an ID, a CVE matching
`^CVE-[0-9]{4}-[0-9]{4,}$`, a baseline, a rationale, and at least one assumption.
The [schema reference](../docs/contracts.md) defines all required and forbidden
fields. This example shows the three evidence kinds:

```yaml
schema_version: 1
decisions:
  - id: example-disabled-feature
    cve: CVE-2024-0001
    baseline: release-1
    rationale: The reviewed vulnerable feature was disabled.
    assumptions:
      - id: feature-disabled
        kind: config
        path: build-config.json
        key: FEATURE_X
        expected_present: true
        expected_value: 'n'
      - id: source-unchanged
        kind: file
        path: src/parser.c
        expected_sha256: '<64 lowercase hex digits>'
      - id: retained-patch
        kind: patch
        path: patches.json
        key: upstream-fix-abc
        expected_present: true
        expected_sha256: '<64 lowercase hex digits>'
```

The CVE is illustrative, and the hash placeholders must be replaced before
loading this manifest. Config exports map keys to strings. Patch exports map
patch IDs to lowercase SHA-256 strings. Both reject duplicate keys. For config
or patch assumptions, `expected_present: true` requires the expected value or
hash. An empty config string is a valid expected value. With
`expected_present: false`, the key must be absent and no expected value or hash
may be supplied.

A changed value or hash, a missing expected key, or an unexpected key requires
review. A missing, unreadable, or invalid evidence file, an unsupported file
type, or an unsafe path is unverifiable. A missing key in a valid inventory is
different from a missing inventory file. Inventory results say only whether
the declared entry matches; they do not prove that a patch is present or absent
in firmware.

## Results and input handling

Unavailable evidence takes precedence over changed assumptions, which take
precedence over matches. Reports retain every observation, so an unavailable
file does not hide a change found elsewhere. Decisions and assumptions are
sorted by ID. Reports include the schema version, decision context, expected
and observed evidence, status, reason, and summary counts. They omit timestamps,
machine-specific absolute root paths, and environment dumps. Reports may expose
configuration values and the reasoning behind decisions, so readers should
review them before sharing.

Evidence paths must stay beneath the supplied root. They must be relative, use
`/` separators, and contain no `..` components or symbolic links. On Linux,
collection uses open directory handles to avoid reopening a path after a
separate safety check. Only regular files are read. The size limits are 1 MiB
for a manifest, 16 MiB for each JSON export, and 1 GiB for each file being hashed.
Exceeding a limit must never produce an unchanged result.

Hashing checks for cancellation and changes in file size or modification time,
using one open file handle. Inputs must remain unchanged throughout a run.
These checks do not guarantee a consistent snapshot if another process
modifies files deliberately and restores their metadata.

## Go API and component responsibilities

The module path is `github.com/firmdura/triageguard`. Its public functions are:

```go
LoadManifest(io.Reader) (Manifest, error)
Check(context.Context, Manifest, root string) (Report, error)
WriteJSON(io.Writer, Report) error
WriteMarkdown(io.Writer, Report) error
```

Changed assumptions and unavailable evidence are reported as results. Invalid
manifests, evidence-root setup failures, and cancellation return errors. The
library must not exit the process or depend on process-global state.

Shared types and interfaces belong in `internal/contracts`, with public aliases
in `pkg/triageguard/types.go`. Internal packages import the shared contracts
rather than the public package. Collection reads evidence, evaluation compares
it and assigns statuses, writers format the results, and the CLI chooses exit
codes and handles output errors. No component modifies inputs or makes network
requests during a check.

## Verification and documentation

The required final checks are:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o bin/triageguard ./cmd/triageguard
./scripts/acceptance.sh
./scripts/test-library.sh
```

Acceptance tests run the built CLI against matching, changed, and unavailable
evidence. They check both report formats and exit codes, confirm that inputs
remain unchanged, and compare repeated output byte for byte. The library smoke
test creates a temporary Go module with a local `replace` directive, imports
only the public package, and exercises the same cases. The documented container
workflow uses `./scripts/verify-linux.sh` with networking disabled after
preparation. All required tests must run; none may be silently skipped.

The README and reference guides cover installation, the Linux environment and
container workflow, a five-minute example, schemas, statuses, reason codes,
exit codes, CI use, the Go API, size limits, report sensitivity, troubleshooting,
and how to review a changed decision. Examples include the exact synthetic
inputs and expected reports. Original code and examples use Apache-2.0, with
third-party licenses and attribution preserved. Verification pins Go 1.27.4 and
the versions in `go.mod`.
