# Recheck a synthetic firmware decision

This walkthrough shows how TriageGuard identifies assumptions that need another
human review. It uses fictional firmware files included in this repository. You
do not need another repository, customer data, a scanner, or network access
after preparing dependencies.

The example uses `CVE-2024-0001` as an illustrative identifier. It makes no claim
about a real affected product. Matching assumptions do not establish whether a
CVE affects a product, whether a fix works, or whether the product is secure or
compliant.

The commands below require Linux, **Go 1.27.4**, and GNU coreutils. Run them from
the repository root. On macOS, use the [Linux container workflow](usage.md#build-and-environment)
instead: run `./scripts/verify-linux.sh prepare`, followed by
`./scripts/verify-linux.sh`. The second command runs this walkthrough and the
full verification suite inside the container.

Keep the inputs unchanged while a check runs. Reports include rationale,
configuration values, and hashes, so review them before sharing.

## Prepare once, then run offline

Download the pinned dependency while network access is available:

```sh
GOTOOLCHAIN=local go version  # must show go1.27.4
GOTOOLCHAIN=local go mod download
```

Then run the walkthrough and the library check:

```sh
./scripts/demo.sh
./scripts/test-library.sh
```

Both scripts disable Go module and toolchain downloads and use the prepared
cache. If a dependency is missing, the script fails; download it before trying
again.

`demo.sh` builds the CLI and runs all three cases in JSON and Markdown. It
compares each report byte for byte with its expected output.
`test-library.sh` creates a temporary Go module outside the repository, imports
`github.com/firmdura/triageguard/pkg/triageguard`, and compares its reports and
exit codes with the CLI and the same expected files.

Both scripts check that the original example files retain their contents,
permissions, sizes, and modification times. They remove their temporary
directories when they finish, including after a failed check.

## The original assumptions

The [manifest](../examples/firmware/decisions.yaml) records a fictional review
of baseline `synthetic-release-1`. A baseline is the version or build that was
reviewed. This decision relies on three assumptions:

| Assumption | Evidence | Expected value |
| --- | --- | --- |
| `feature-disabled` | `build-config.json`, key `FEATURE_X` | The exact string `n` |
| `source-retained` | Regular file `src/parser.c` | SHA-256 hash of the included source file |
| `patch-record-retained` | `patches.json`, ID `synthetic-feature-default` | SHA-256 hash recorded for the included patch |

The [source](../examples/firmware/evidence/src/parser.c) and
[patch](../examples/firmware/evidence/patches/feature-default.patch) are original
examples covered by the [Apache-2.0 license](../LICENSE). The manifest and
[checksum file](../testdata/demo/known-bytes.sha256) record both hashes; the
patch inventory records the patch hash. To inspect and verify them, run:

```sh
sha256sum examples/firmware/evidence/src/parser.c \
  examples/firmware/evidence/patches/feature-default.patch
sha256sum --check testdata/demo/known-bytes.sha256
```

The patch inventory is a JSON export that you supply. A matching patch ID and
hash mean only that the inventory entry matches the manifest. They do not
prove that the patch was applied or that the firmware is fixed. The walkthrough
verifies the included patch file separately; TriageGuard itself does not apply
patches or run a build.

## Three runs

`demo.sh` copies the evidence into temporary directories and checks three
cases. Each report keeps the original decision, baseline, rationale, and all
three assumption results.

| Run | Change to the temporary evidence | Report status | Unchanged assumptions | Changed assumptions | Unavailable assumptions | Exit code |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| unchanged | None | `unchanged` | 3 | 0 | 0 | 0 |
| feature-enabled | Replace the configuration export so `FEATURE_X` is `y` | `review-required` | 2 | 1 | 0 | 1 |
| missing-evidence | Keep the feature enabled and remove `src/parser.c` | `unverifiable` | 1 | 1 | 1 | 2 |

The enabled feature produces reason `value-changed`. The missing source file
produces `evidence-missing`. Unavailable evidence sets the overall status to
`unverifiable`, but the configuration mismatch stays visible in the report.
A missing file is not treated as a hash mismatch or a match.

These are the exit codes of the individual checks. The scripts themselves exit
with code 0 when all expected results are verified.

Open the expected reports to see the complete results:

- Unchanged: [JSON](../testdata/demo/expected/unchanged.json), [Markdown](../testdata/demo/expected/unchanged.md).
- Feature enabled: [JSON](../testdata/demo/expected/feature-enabled.json), [Markdown](../testdata/demo/expected/feature-enabled.md).
- Missing evidence, with the configuration change still visible: [JSON](../testdata/demo/expected/missing-evidence.json), [Markdown](../testdata/demo/expected/missing-evidence.md).

To run the same sequence yourself without editing the original examples, use
the following commands. They build a temporary CLI and print each report and
exit code:

```sh
(
  set -eu
  export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GONOPROXY=none GOWORK=off
  work=$(mktemp -d)
  trap 'rm -rf "$work"' 0
  go build -mod=readonly -buildvcs=false -o "$work/triageguard" ./cmd/triageguard
  cp -R examples/firmware/evidence "$work/evidence"

  check_exit=0
  "$work/triageguard" check --manifest examples/firmware/decisions.yaml \
    --root "$work/evidence" --format json || check_exit=$?
  printf 'unchanged exit: %s\n' "$check_exit"

  cp testdata/demo/feature-enabled.json "$work/evidence/build-config.json"
  check_exit=0
  "$work/triageguard" check --manifest examples/firmware/decisions.yaml \
    --root "$work/evidence" --format json || check_exit=$?
  printf 'feature-enabled exit: %s\n' "$check_exit"

  rm "$work/evidence/src/parser.c"
  check_exit=0
  "$work/triageguard" check --manifest examples/firmware/decisions.yaml \
    --root "$work/evidence" --format markdown || check_exit=$?
  printf 'missing-evidence exit: %s\n' "$check_exit"
)
```

## Use the public Go API

The complete [Go example](../examples/go-check/main.go) calls `LoadManifest`,
`Check`, and either `WriteJSON` or `WriteMarkdown`. It handles setup errors
separately from report statuses. `Check` returns changed assumptions and
unavailable evidence in the report with a nil error. Invalid manifests,
failures to set up the evidence root, and cancellation return an error. The
example program chooses its process exit codes; the library never exits the
process.

Run `./scripts/test-library.sh` to compile that example outside the repository's
module. The script uses a local `replace` directive so it checks your source
checkout without downloading the released module. It verifies all three cases
in both report formats. To install the published version instead, follow the
[library installation instructions](../README.md#use-the-go-library).

## Reassess a changed decision

Preserve the original decision and report. Have a human reviewer investigate
why an assumption changed and whether the original reasoning still applies.
If evidence is unavailable, restore or regenerate it and check again before
drawing conclusions.

After a new review, record a new decision with its baseline and explicit
expectations. Do not overwrite the historical evidence just to obtain exit
code 0. See the [version 1 contracts](contracts.md) for the complete schema,
limits, and reason codes, and the [design guide](design.md) for the tool's
scope.
