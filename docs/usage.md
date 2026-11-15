# CLI and evidence guide

TriageGuard rechecks the assumptions behind a previous human decision about a
CVE. You record the decision and its expected evidence in a YAML manifest, then
check it against local files. Start with the [walkthrough](tutorial.md) to see
an example.

Matching assumptions do not establish whether a CVE affects a product, whether
a fix works, or whether the product is secure or compliant. TriageGuard does
not scan for vulnerabilities, determine whether vulnerable code can be reached,
apply fixes, or create or update VEX records.

## Build and environment

Evidence checks require Linux. Building and verifying the source requires
exactly **Go 1.27.4**, GNU coreutils, and a C compiler with CGO enabled for race
tests. The [README](../README.md) provides the native Linux build commands.
To use the supplied Linux container on macOS or Linux, run these commands from
the repository root:

```sh
./scripts/verify-linux.sh prepare
./scripts/verify-linux.sh
```

The first command downloads the pinned Linux/arm64 Go image and prepares a
cache of dependencies. The second runs verification with
`--pull=never --network=none`, using that cache and a temporary writable copy
of your current source. The copy includes local edits and new files that Git
does not ignore. Avoid editing the working tree while the script is copying it.
Your repository and input evidence are not mounted into the container.

The host needs Docker, Git, Bash, and tar. Docker must support Linux/arm64
containers, through emulation if necessary. The image digest and Go dependency
versions are pinned in the source.

## Commands and exit codes

After building the CLI, run:

```sh
bin/triageguard check --manifest decisions.yaml --root ./evidence --format json
bin/triageguard check --manifest decisions.yaml --root ./evidence --format markdown
bin/triageguard --help
bin/triageguard --version
```

These commands assume your manifest is `decisions.yaml` and your evidence is in
`./evidence`. Replace the paths as needed. If you installed a release binary on
your `PATH`, use `triageguard` in place of `bin/triageguard`.

Both `--manifest` and `--root` are required. The output format defaults to
`json`; the only other supported format is `markdown`. Options accept either
`--name value` or `--name=value`. Unknown options, repeated options, extra
positional arguments, missing or empty values, and unsupported formats all
produce exit code 2.

Use `--help` or `-h` by itself, either after the executable name or after
`check`. Use `--version` by itself after the executable name. These commands
exit with code 0 when their output is written successfully. Development builds
display `triageguard dev`; packaged builds display their release version.

The manifest must be a regular file. The evidence root must be an existing
Linux directory; an empty path, missing path, path to another file type, or
symlink as the final path component is an error. Treat the root path as trusted
setup input. TriageGuard keeps the opened root directory handle and resolves
evidence paths beneath it.

| Exit code | Meaning |
| ---: | --- |
| 0 | All assumptions match; the report status is `unchanged` |
| 1 | At least one assumption changed and all evidence was available; the report status is `review-required` |
| 2 | At least one assumption is `unverifiable`, or invalid input, a setup or I/O failure, or cancellation prevented a successful run |

The report goes to standard output. Diagnostic messages go to standard error.
An invalid manifest, failure to set up the evidence root, or cancellation
produces no report. If an individual evidence file is unavailable, the CLI
produces a complete report with exit code 2 and no diagnostic message. A failed
output write, including a broken pipe, also produces exit code 2; discard any
partial output. SIGINT and SIGTERM cancel a check, including any file hashing
in progress.

## Manifest schema

A manifest records each decision's baseline, rationale, and assumptions. The
baseline identifies the version or build that was reviewed; the rationale
explains the human decision. The [version 1 contracts](contracts.md) describe
the complete schema and Go types. The [example manifest](../examples/firmware/decisions.yaml)
contains real hashes of the fictional files included in the repository.

Here is a shorter example showing two assumption types:

```yaml
schema_version: 1
decisions:
  - id: historical-review
    cve: CVE-2024-0001
    baseline: release-1
    rationale: A synthetic prior human review assumed FEATURE_X was disabled.
    assumptions:
      - id: feature-disabled
        kind: config
        path: build-config.json
        key: FEATURE_X
        expected_present: true
        expected_value: 'n'
      - id: inventory-exclusion
        kind: patch
        path: patches.json
        key: not-in-inventory
        expected_present: false
```

`CVE-2024-0001` is an illustrative identifier, not a claim about an affected
product. At the top level, a manifest requires `schema_version` set to the
integer `1` and a nonempty `decisions` list. Each decision requires:

- Nonblank `id`, `baseline`, and `rationale` strings.
- A `cve` string matching `^CVE-[0-9]{4}-[0-9]{4,}$`.
- A nonempty `assumptions` list.

Decision IDs must be unique. Assumption IDs must be unique across the entire
manifest. Each assumption needs a nonblank `id`, a supported `kind`, and a
nonempty string `path`. Its remaining fields depend on the kind and whether a
key is expected to be present:

| Kind and expectation | Additional required fields | Forbidden fields |
| --- | --- | --- |
| config, present | `key`, `expected_present: true`, string `expected_value` | `expected_sha256` |
| config, absent | `key`, `expected_present: false` | `expected_value`, `expected_sha256` |
| file | `expected_sha256` | `key`, `expected_present`, `expected_value` |
| patch, present | `key`, `expected_present: true`, `expected_sha256` | `expected_value` |
| patch, absent | `key`, `expected_present: false` | `expected_value`, `expected_sha256` |

SHA-256 values must contain exactly 64 lowercase hexadecimal digits. The `key`
field must be a string; an empty string is allowed. Setting
`expected_value: ''` requires the key to be present with an empty string value.
That is different from requiring the key to be absent.

Forbidden fields are rejected even if their value is `null`. TriageGuard also
rejects unknown fields, duplicate YAML keys, aliases (including merge aliases),
incorrect value types, duplicate IDs, multiple YAML documents, and unsupported
schema versions. It does not convert booleans or numbers into strings. An
unused YAML anchor is allowed, but a reference to an anchor is not.

## Evidence exports and paths

A configuration export is a single JSON object whose values are strings:

```json
{"FEATURE_X":"n","EMPTY":""}
```

A patch export is a JSON object that maps patch IDs to lowercase SHA-256
strings. See the [example inventory](../examples/firmware/evidence/patches.json),
which matches the example manifest. Create these exports as part of your own
engineering process. TriageGuard does not parse BitBake or Buildroot
configuration, run builds, or fetch inventories.

Both export formats reject duplicate keys, non-string values, extra data after
the JSON object, invalid UTF-8, and unpaired Unicode surrogates. Duplicate keys
are rejected even when different escape sequences spell the same key. Any
malformed SHA-256 value invalidates the entire patch export, including a value
for a patch that the manifest does not mention. Valid extra entries do not
affect assumptions about other keys.

A missing key in a valid export is evidence that the key is absent. A missing
or malformed export file means the evidence is unavailable. For example, a
valid empty object satisfies an assumption that a key is absent; a missing
file does not.

Evidence paths are relative to the root directory and use `/` as the separator.
They must not contain empty components, `.` or `..` components, backslashes,
NUL characters, or symlinks in any component. Absolute paths are also rejected.
Only regular files are read. A nonempty but unsafe path in the manifest produces
an `unverifiable` result with reason `unsafe-path` for that assumption; the
other assumptions are still checked.

## Results and reason codes

TriageGuard keeps every assumption's result. For both a decision and the whole
report, the overall status is `unverifiable` if any assumption cannot be
verified. Otherwise, it is `review-required` if any assumption changed, or
`unchanged` if all assumptions match.

An assumption that requires a key to be absent matches when that key is absent
from a valid export. A missing file is always unavailable evidence, even if
the assumption requires a key to be absent.

| Assumption reason | Status | Meaning |
| --- | --- | --- |
| `match` | `unchanged` | The value, hash, or expected absence matches |
| `value-changed` | `review-required` | The configuration string differs |
| `hash-changed` | `review-required` | The file hash or the hash recorded for the patch ID differs |
| `key-missing` | `review-required` | A key expected to be present is missing from a valid export |
| `key-unexpected` | `review-required` | A key expected to be absent is present |
| `evidence-missing` | `unverifiable` | The evidence file does not exist |
| `evidence-unreadable` | `unverifiable` | A permission or I/O error prevented opening, reading, or inspecting the file |
| `invalid-export` | `unverifiable` | The configuration or patch JSON export is invalid |
| `unsafe-path` | `unverifiable` | The path contains a forbidden component or a symlink |
| `unsupported-file-kind` | `unverifiable` | The evidence is not a regular file, or an intermediate path component is not a directory |
| `limit-exceeded` | `unverifiable` | The evidence exceeds its size limit |
| `evidence-changed` | `unverifiable` | The file's observed size or modification time changed while it was read |

Decisions and reports use `all-unchanged` for an `unchanged` status,
`assumptions-changed` for `review-required`, and `evidence-unavailable` for
`unverifiable`.

For patch assumptions, a missing ID with `expected_present: true` means the
inventory changed. A missing ID with `expected_present: false` matches the
expectation. Neither result proves whether a patch is present in firmware.

Reports include the schema version; each decision's ID, CVE, baseline, and
rationale; and each assumption's kind, path, key (where applicable), expected
evidence, observed evidence, status, and reason. They also count decisions and
assumptions by status. Decisions and assumptions are sorted by ID.

JSON reports omit generated timestamps, absolute evidence-root paths,
environment dumps, and raw operating system diagnostics. Optional fields
preserve the difference between a missing value and an empty string. Markdown
explains result codes in plain English and uses JSON quoting to preserve exact
evidence. Ordinary single spaces remain readable; leading, trailing, and repeated
spaces appear as `\u0020`, making significant whitespace and empty strings
visible. See the
[expected reports](../testdata/demo/expected) for examples.

## Limits and handling reports

| Input | Maximum size |
| --- | ---: |
| YAML manifest | 1 MiB (1,048,576 bytes) |
| Each JSON export | 16 MiB (16,777,216 bytes) |
| Each regular file hashed | 1 GiB (1,073,741,824 bytes) |

An input that exceeds a limit is never reported as unchanged. File hashing uses
a single open handle and checks for cancellation and changes to the observed
size or modification time. Keep every input unchanged for the entire run.
These checks do not guarantee a consistent snapshot against a process that is
changing files, especially one that restores the original metadata afterward.
TriageGuard checks only the assumptions you declare. Its report says nothing
about undeclared files, build state, or whether a patch was actually applied.

Reports can expose rationale, keys, configuration values, paths, and hashes.
Review a copy and redact sensitive details before sharing it. Control access
to the originals and preserve historical manifests and reports.

If an assumption changes, have a human reviewer investigate whether the
original reasoning still holds. Restore or regenerate unavailable evidence,
then check it again. After a new review, record a new decision and baseline
rather than changing historical expectations merely to obtain exit code 0.

## CI use

Download dependencies before the CI verification step. A Linux job with the
built CLI can save the report and preserve the exit code, including when a
review is needed:

```sh
check_exit=0
bin/triageguard check --manifest examples/firmware/decisions.yaml \
  --root examples/firmware/evidence --format json > report.json 2> diagnostics.log || check_exit=$?
case "$check_exit" in
  0) printf '%s\n' 'Recorded assumptions match.' ;;
  1) printf '%s\n' 'A human review is required.' ;;
  2) printf '%s\n' 'Check the report for unavailable evidence and the diagnostic log for errors. Discard partial output after a write failure.' ;;
esac
exit "$check_exit"
```

This CI check detects changes in recorded evidence. It does not approve a CVE
decision or replace a scanner, VEX record, security review, or compliance
process. Use the [Go API](api.md) if your application needs the structured
report directly.
