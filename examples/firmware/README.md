# Synthetic firmware decision

This directory contains fictional firmware files for the
[walkthrough](../../docs/tutorial.md). All inputs are original examples covered
by the repository's [Apache-2.0 license](../../LICENSE). They contain no customer
data, production firmware, or third-party patch text. `CVE-2024-0001` is an
illustrative identifier; the example makes no claim about a real affected
product.

The [`decisions.yaml`](decisions.yaml) manifest records a previous human decision
and three assumptions: `FEATURE_X` remains `n`, the contents of `src/parser.c`
match its recorded SHA-256 hash, and a patch inventory entry retains its
recorded SHA-256 hash. The hashes were calculated from the source and patch
files included here. You can inspect the patch to see exactly which content
its hash represents.

The patch assumption checks only the entry in `patches.json`. It does not hash
the patch file itself, prove that the patch was applied, or establish that the
firmware is fixed. The walkthrough separately checks the source and patch files
against `testdata/demo/known-bytes.sha256`. Neither TriageGuard nor the
walkthrough applies the patch.

Follow the [walkthrough](../../docs/tutorial.md) to prepare dependencies, then
run `./scripts/demo.sh` and `./scripts/test-library.sh` from the repository root
on Linux. Both scripts use temporary directories and compare their reports
with the [expected outputs](../../testdata/demo/expected).
