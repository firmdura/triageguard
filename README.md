# TriageGuard

[![Latest release](https://img.shields.io/github/v/release/firmdura/triageguard)](https://github.com/firmdura/triageguard/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/firmdura/triageguard/pkg/triageguard.svg)](https://pkg.go.dev/github.com/firmdura/triageguard/pkg/triageguard)

Know when to revisit a previous CVE assessment.

TriageGuard checks whether the evidence behind a human decision about a CVE
still matches the assumptions recorded at the time. For example, a review may
have relied on a feature being disabled, a source file staying unchanged, or a
particular patch appearing in an inventory. TriageGuard rechecks those facts
and reports any changes or evidence it could not verify.

You record each decision in a YAML manifest: the version or build reviewed
(the **baseline**), the reasoning behind the decision, and the **assumptions**
to check. TriageGuard v1.0.0 provides a Go command-line tool and library. Both
read local files without modifying them or making network requests during a
check.

**An `unchanged` result means only that the recorded assumptions still match.**
It does not establish whether a CVE affects your product, whether a fix works,
or whether the product is secure or compliant. TriageGuard does not scan for
vulnerabilities, determine whether vulnerable code can be reached, apply
patches, or create or update Vulnerability Exploitability eXchange (VEX)
records. You supply configuration and patch inventories in the supported JSON
formats.

## Try the five-minute example

The [walkthrough](docs/tutorial.md) uses fictional firmware files included in
this repository. It demonstrates three results: matching assumptions (exit 0),
a configuration change (exit 1), and a missing source file alongside that
change (exit 2). It compares the JSON and Markdown reports with the expected
reports included in the repository. The example CVE identifier is illustrative;
it makes no claim about a real affected product.

TriageGuard checks evidence on **Linux**. To try the example on macOS, or to use
the same verification environment on Linux, install Docker with support for
Linux/arm64 containers. Then run:

```sh
git clone https://github.com/firmdura/triageguard.git
cd triageguard
./scripts/verify-linux.sh prepare  # download the image and Go dependencies
./scripts/verify-linux.sh          # run the walkthrough and full suite offline
```

The verification command copies your current source into a temporary Linux
container. It checks local edits as well as committed files and does not mount
your repository into the container. It does not create a binary on your host.
The container uses Linux/arm64, so hosts with another architecture need Docker
emulation support. See [troubleshooting](docs/troubleshooting.md) for details.

To build and run directly on Linux, install **Go 1.27.4**, GNU coreutils, and a
C compiler for the race tests. From the repository root, run:

```sh
GOTOOLCHAIN=local go mod download  # download dependencies before going offline
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GONOPROXY=none GOWORK=off GOENV=off
go build -o bin/triageguard ./cmd/triageguard
./scripts/demo.sh
./scripts/test-library.sh
```

You can also download a prebuilt Linux binary from the
[v1.0.0 release](https://github.com/firmdura/triageguard/releases/tag/v1.0.0).
The [installation guide](docs/distribution.md) explains how to choose an
archive, verify its checksum, and install the executable.

## Check your evidence

After building from source, run the CLI against the example manifest and
evidence directory:

```sh
bin/triageguard check --manifest examples/firmware/decisions.yaml \
  --root examples/firmware/evidence --format json
bin/triageguard --help
```

Replace those paths with your own manifest and evidence directory when you are
ready to check a real decision. If you installed a release binary on your
`PATH`, use `triageguard` in place of `bin/triageguard`.

| Exit code | Meaning |
| ---: | --- |
| 0 | Every recorded assumption is `unchanged` |
| 1 | At least one assumption is `review-required`, and none is `unverifiable` |
| 2 | Invalid input, an I/O failure, cancellation, or at least one `unverifiable` assumption |

The `check` command writes its report to standard output and diagnostic messages
to standard error. An invalid manifest or a failure to open the evidence root
produces no report. Keep all inputs unchanged while a check is running; the
file metadata checks cannot guarantee a consistent snapshot if another process
is changing files. Reports can contain sensitive configuration values, keys,
rationale, and hashes, so review them before sharing.

When an assumption changes, preserve the old decision and investigate the
change. Record a new baseline and decision after a human review. See the
[CLI and evidence guide](docs/usage.md) for the schemas and full behavior.

## Use the Go library

Import `github.com/firmdura/triageguard/pkg/triageguard`. The library's
`LoadManifest`, `Check`, `WriteJSON`, and `WriteMarkdown` functions use the same
validation rules and result meanings as the CLI. Changed assumptions and
unavailable evidence appear in the report. Invalid manifests, failures to set up
the evidence root, and cancellation return errors. The library never exits your
process.

In your application's Go module, use Go 1.27.4 and download the released
package while network access is available:

```sh
GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  go get github.com/firmdura/triageguard/pkg/triageguard@v1.0.0
```

See the [API guide](docs/api.md), [runnable Go example](examples/go-check/main.go),
and [versioned package documentation](https://pkg.go.dev/github.com/firmdura/triageguard@v1.0.0/pkg/triageguard).

## Verify a source checkout

The Docker verification command above runs the following checks and the
walkthrough, using a temporary source copy with networking disabled:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o bin/triageguard ./cmd/triageguard
./scripts/acceptance.sh
./scripts/test-library.sh
```

[Release packaging](docs/distribution.md) builds versioned Linux/arm64 and
Linux/amd64 binary archives, an archive of the tracked source, license notices,
and SHA-256 checksums from a clean commit. Generated files in `bin/` and `dist/`
are kept out of Git. Running the packaging script creates local files; it does
not publish a release or change repository visibility.

## Further reading

- [CLI, schemas, result statuses, limits, and CI use](docs/usage.md)
- [Version 1 schema and API contracts](docs/contracts.md)
- [Five-minute walkthrough and expected reports](docs/tutorial.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Distribution and reproducible builds](docs/distribution.md)
- [Design and scope](docs/design.md)

## About Firmdura

This repository contains a standalone verification utility from
[Firmdura](https://firmdura.com). Firmdura's commercial offer is shared embedded
Linux security maintenance through versioned security layers or patch overlays
for agreed user-space components.

## License

Original code and synthetic examples use the [Apache-2.0 license](LICENSE).
Distributions retain the Go and YAML dependency licenses and attribution; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
