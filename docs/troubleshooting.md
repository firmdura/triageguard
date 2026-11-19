# Troubleshooting

## Linux and toolchain setup

If you see `evidence collection requires Linux`, the check is running on an
unsupported operating system. From a clone of the repository, use the pinned
Linux container. You need Docker, Git, Bash, and tar on the host:

```sh
./scripts/verify-linux.sh prepare
./scripts/verify-linux.sh
```

The image is pinned by digest and includes Linux/arm64, Go 1.27.4, GNU tools,
and the C compiler needed for race tests. If your Docker host uses another
architecture, it needs Linux/arm64 emulation. You can also run the checks on a
native Linux host with the required tools. For native runs, set
`GOTOOLCHAIN=local` and confirm that `go version` shows `go1.27.4`. The toolchain
directive in `go.mod` alone does not enforce that exact version.

If Docker cannot connect, start the Docker engine and check your configuration
with `docker context show` and `docker info`. The scripts send files through
standard input, so Docker does not need to mount macOS temporary directories.
If the offline command cannot find the image or dependency cache, it fails with
instructions to run preparation. The `prepare` command downloads the image and
pinned dependency. Verification uses the prepared image and cache with
`--network=none`, `GOPROXY=off`, and `GOSUMDB=off`.

If Go reports a missing cached dependency, run `prepare` again while network
access is available, then return to offline verification. The cache uses a
named Docker volume, `triageguard-go1.27.4-cache`. To use another dedicated
volume, set `TRIAGEGUARD_CACHE_VOLUME`. Preparation sets that volume's ownership
for your current user and group. Use separate volumes for separate local users.

## Exit 2 with no report

Read the diagnostic message on standard error. Check that you supplied the
required flags and chose either `json` or `markdown` for the format. Unknown or
duplicate flags and extra positional arguments are rejected.

The manifest must be a regular file containing one valid version 1 YAML
document. The [schema reference](contracts.md) explains required types,
forbidden fields, YAML aliases, and unique-ID rules. The evidence root must be
an existing directory; an empty path, missing directory, nondirectory path, or
symbolic link as the final component is rejected. The CLI needs read access to
its inputs, not write access. Cancellation through SIGINT or SIGTERM also
returns 2 without a report.

## Exit 2 with a complete report

An `unverifiable` observation means that TriageGuard could not read or trust the
evidence. Look at its reason code to find the cause: a missing or unreadable
file, invalid export, unsafe path, unsupported file type, size limit, or a file
that changed during reading. Restore the intended regular file or export the
JSON map again, then rerun the check while no process is changing the inputs.
Keep the original assumptions and changed results while investigating; deleting
an assumption would hide the unresolved question.

A file can be accepted by a general JSON parser and still fail TriageGuard's
validation. Duplicate keys, null or numeric values, invalid Unicode, trailing
JSON documents, and malformed patch hashes anywhere in an inventory invalidate
the export. Config values must be strings. A missing key is different from a
key whose value is an empty string.

## Exit 1

At least one assumption differs from its recorded expectation, and all evidence
was available. Keep the report and historical decision, investigate the change,
and arrange a new human review. A changed inventory entry tells you that the
exported inventory differs; it does not tell you whether a patch was applied.
A matching hash or value does not establish CVE applicability, remediation,
security, or compliance.

## Broken output pipes or partial reports

An output failure returns 2 with a diagnostic message on standard error. This
can happen if a downstream process closes a pipe, the disk fills up, or writing
fails for another reason. Discard partial output and rerun with a working
destination. For CI use, write to a file, retain the exit code, and inspect
diagnostics as shown in the [CI example](usage.md#ci-use).

Exit 2 can also mean unavailable evidence. In that case, TriageGuard produces a
complete report whose status and reason codes explain the evidence failure.
Check both the report and diagnostics to distinguish the two cases.

## Public import and local distribution

Use the versioned `go get` command
in the [API guide](api.md) while network access is available. If an offline run
cannot find the module, download it first, then return to the offline
environment. Public module downloads do not require repository credentials.

From a clone, `./scripts/test-library.sh` creates a temporary Go module with a
local `replace` directive and imports the public package from your checkout.
It needs no credentials or network access once dependencies are prepared.

Release packaging requires a clean, committed worktree and an empty or absent
output directory. Verify and commit your changes before packaging, and use a
fresh output directory for each rebuild. The [distribution guide](distribution.md)
covers checksums, source archives, and license notices.
