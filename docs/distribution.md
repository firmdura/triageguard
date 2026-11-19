# Releases and reproducible builds

Use the release binaries to run TriageGuard on Linux, or rebuild the archives
from the tagged source to compare their checksums.

## Install a released Linux binary

From the [v1.0.1 release page](https://github.com/firmdura/triageguard/releases/tag/v1.0.1),
download `SHA256SUMS` and the archive for your Linux architecture:

- `triageguard-1.0.1-linux-arm64.tar.gz` for arm64.
- `triageguard-1.0.1-linux-amd64.tar.gz` for amd64, also called x86-64.

Put both downloaded files in the same directory. Open a terminal in that
directory and verify the checksum before extracting. On Linux with GNU
coreutils:

```sh
sha256sum --ignore-missing --check SHA256SUMS
```

This checks the archives present in the directory and skips the other entries
in `SHA256SUMS`. Confirm that the archive you downloaded is reported as `OK`.
On macOS, run `shasum -a 256 ARCHIVE.tar.gz` with your archive's filename and
compare the hash with that file's entry in `SHA256SUMS`.

The following example extracts and runs the arm64 executable on Linux/arm64.
For amd64, replace `arm64` with `amd64` in all three commands:

```sh
tar -xzf triageguard-1.0.1-linux-arm64.tar.gz
./triageguard-1.0.1-linux-arm64/triageguard --version
./triageguard-1.0.1-linux-arm64/triageguard --help
```

To make `triageguard` available as a command, copy the extracted executable into
a directory listed in your `PATH`. The binary archives do not include a compiler
or dependency cache. To build or run the source examples, download and extract
the source archive and follow its README. See the [verification limits](#archive-contents-and-verification-limits)
below for the checks performed on each architecture.

## Prepare and verify

To reproduce v1.0.1, check out the release tag in a clean working directory:

```sh
git clone --branch v1.0.1 https://github.com/firmdura/triageguard.git triageguard-v1.0.1
cd triageguard-v1.0.1
```

You need Docker, Git, Bash, and tar on the host. The scripts use the pinned
Linux/arm64 image with Go 1.27.4 defined in `scripts/linux-common.sh`. Hosts with
another architecture need compatible emulation.

```sh
./scripts/verify-linux.sh prepare
./scripts/verify-linux.sh
./scripts/build-release.sh v1.0.1
```

The first command downloads the image and dependencies into a named cache.
The remaining commands use that image and cache with
`--pull=never --network=none`; they do not download a toolchain or dependencies.
Verification copies the current source into a temporary container, then runs
the unit tests, race tests, vet, CLI build, acceptance tests, library smoke test,
and walkthrough. Keep the source unchanged while it is being copied. All of
these checks are required.

Packaging requires a clean worktree and archives the exact `HEAD` commit. It
rejects tracked local instruction files and generated `bin/` or `dist/` files.
Ignored local files are excluded from the source archive. Pending edits are
not built, and the script does not create a commit.

With `v1.0.1` as the version argument, output goes into `dist/v1.0.1/`. An optional
second argument selects another directory, which must be empty or not yet
exist. A nonempty directory is rejected to avoid mixing files from different
builds.

## Archive contents and verification limits

| File | Contents |
| --- | --- |
| `triageguard-1.0.1-linux-arm64.tar.gz` | Linux/arm64 executable, build information, usage note, licenses, and notices |
| `triageguard-1.0.1-linux-amd64.tar.gz` | Linux/amd64 executable built by cross-compilation, with the same notices |
| `triageguard-1.0.1-source.tar.gz` | Tracked source under `triageguard-1.0.1/`, including documentation, examples, and notices |
| `SHA256SUMS` | SHA-256 hashes of the three archives |

Packaging runs the arm64 executable to check its version. Release verification
runs the full offline acceptance suite on Linux/arm64 and checks the packaged
arm64 executable. For v1.0.1, the cross-compiled amd64 executable reported
its version under emulation. Native amd64 acceptance was not tested.

Both binaries use `CGO_ENABLED=0`, `GOAMD64=v1`, `GOARM64=v8.0`, `-trimpath`,
`-buildvcs=false`, a cleared build ID, stripped debug and symbol data, and
`-X main.version=v1.0.1`. Build information records the commit, target, and
toolchain. The binary archives use fixed file modes, ordering, ownership, and
modification times. Compression runs in the pinned container and omits gzip
filename and time metadata. The source archive uses Git's committed tree and
time metadata and is compressed in the same container.

To reproduce the files byte for byte, use the same source commit, version,
toolchain, dependencies, and packaging script. Identical archive bytes do not
establish security or CVE applicability.

## Rebuild and compare

From the same clean commit, build into two empty directories and compare the
checksums:

```sh
./scripts/build-release.sh v1.0.1 dist/rebuild-a
./scripts/build-release.sh v1.0.1 dist/rebuild-b
cmp dist/rebuild-a/SHA256SUMS dist/rebuild-b/SHA256SUMS
```

Each packaging run also verifies its generated checksums. To check the default
output directory on Linux:

```sh
(cd dist/v1.0.1 && sha256sum --check SHA256SUMS)
```

That command checks all three archives created by packaging. On macOS, run
`shasum -a 256 -c SHA256SUMS` from the output directory instead. For a single
downloaded archive, follow the [installation instructions](#install-a-released-linux-binary).

Original code and examples use [Apache-2.0](../LICENSE). Each distribution
includes the project LICENSE, Go LICENSE/PATENTS, YAML LICENSE/NOTICE, and
synthetic fixture attribution in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Packaging compares upstream
license and notice files with the pinned toolchain and module cache.
