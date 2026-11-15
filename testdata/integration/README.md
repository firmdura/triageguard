# Integration fixtures

These synthetic test inputs were created for TriageGuard and are licensed under
Apache-2.0. The illustrative CVE identifier makes no claim about whether a real
product is affected.
Tests copy these files into temporary directories before changing the evidence,
leaving the checked-in files untouched.

The source hash is the SHA-256 of `evidence/source.c`. The patch inventory hash
is the SHA-256 of the UTF-8 text `Synthetic patch content, not an upstream fix.`
followed by one newline. The inventory does not describe a real patch.

`api/main.go` is a test program that imports only the public Go package and
writes its report. Subprocess tests use it to compare the CLI with the public
API. It is not an alternative CLI for users.
