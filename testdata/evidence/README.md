# Synthetic evidence fixtures

These test inputs were created for TriageGuard and use the repository's
Apache-2.0 license. They contain no customer files and make no claim that a
product is affected by a vulnerability.

`config.json` tests ordinary strings, empty values, an empty key, and Unicode
values. In `patches.json`, the hash is the SHA-256 of the text
`synthetic patch bytes` followed by one newline. This inventory example does
not prove that a patch is present in firmware. `source.c` provides a regular
file for hash checks.

Other JSON files test invalid exports. In particular, `bad-utf8.json`
intentionally contains an invalid UTF-8 byte. Tests copy valid fixtures to
temporary directories and never modify the checked-in inputs.

To run the evidence tests on Linux after preparing dependencies:

```sh
go test ./internal/evidence -count=1
go test -race ./internal/evidence
```
