// Package cli implements command parsing and exit behavior over explicit
// adapters. The command wires the public API into these adapters; this package
// depends only on the canonical contracts, never the public facade.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/firmdura/triageguard/internal/contracts"
)

// Operations supplies the public API functions without reversing the internal
// package dependency direction. Every function must be supplied by the command.
type Operations struct {
	LoadManifest  func(io.Reader) (contracts.Manifest, error)
	Check         func(context.Context, contracts.Manifest, string) (contracts.Report, error)
	WriteJSON     func(io.Writer, contracts.Report) error
	WriteMarkdown func(io.Writer, contracts.Report) error
}

const help = `TriageGuard rechecks the assumptions behind a previous CVE assessment.
It compares local evidence with the expectations recorded in a YAML manifest.

Usage:
  triageguard check --manifest PATH --root DIRECTORY [--format json|markdown]
  triageguard check --help
  triageguard --help
  triageguard --version

Check options:
  --manifest PATH       YAML file recording decisions and assumptions (required).
                        The manifest must use schema version 1.
  --root DIRECTORY      Existing directory containing evidence files (required).
  --format FORMAT       Report format: json (default) or markdown.

Help and version:
  --help, -h            Show this help. Use alone or after check.
  --version             Show the version. Use alone.

Checks require Linux. TriageGuard reads inputs without changing them and makes
no network requests during a check. Keep all inputs unchanged while it runs.
The report goes to standard output; diagnostic messages go to standard error.
Invalid arguments or manifests, evidence directory setup failures, and
cancellation produce no report.

Exit codes:
  0  Every recorded assumption matches (unchanged).
  1  At least one assumption changed, and all evidence was available
     (review-required).
  2  At least one assumption could not be verified (unverifiable), or the
     command failed because of invalid input, an I/O error, or cancellation.

An unchanged result does not establish whether a CVE affects your product,
whether a fix works, or whether the product is secure or compliant.
Investigate changed assumptions and record a new decision after a human review.
Restore or correct unavailable evidence and check again before drawing
conclusions. Reports can contain sensitive values and review details, so review
them before sharing.
`

// Run handles one invocation without exiting the process or changing global
// state. version is displayed verbatim by --version. The executable owns signal
// handling and passes its cancellable context here.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, version string, ops Operations) int {
	fail := func(err error) int {
		_, _ = fmt.Fprintf(stderr, "triageguard: %v\n", err)
		return 2
	}
	writeText := func(text string) int {
		n, err := io.WriteString(stdout, text)
		if err == nil && n != len(text) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return fail(fmt.Errorf("write output: %w", err))
		}
		return 0
	}
	if len(args) == 1 {
		switch args[0] {
		case "--help", "-h":
			return writeText(help)
		case "--version":
			return writeText("triageguard " + version + "\n")
		}
	}
	if len(args) == 0 || args[0] != "check" {
		return fail(fmt.Errorf("expected check, --help, or --version"))
	}
	options, showHelp, err := parseCheck(args[1:])
	if err != nil {
		return fail(err)
	}
	if showHelp {
		return writeText(help)
	}
	if ctx == nil {
		return fail(fmt.Errorf("check context is nil"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if ops.LoadManifest == nil || ops.Check == nil || ops.WriteJSON == nil || ops.WriteMarkdown == nil {
		return fail(fmt.Errorf("command API adapters are incomplete"))
	}
	// Nonblocking open plus a regular-file check avoids hanging on a FIFO or
	// device after the executable has installed its context-based signal handler.
	manifestFile, err := os.OpenFile(options.manifest, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fail(fmt.Errorf("open manifest: %w", err))
	}
	info, err := manifestFile.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = manifestFile.Close()
		if err != nil {
			return fail(fmt.Errorf("stat manifest: %w", err))
		}
		return fail(fmt.Errorf("manifest must be a regular file"))
	}
	manifest, loadErr := ops.LoadManifest(contextReader{ctx, manifestFile})
	closeErr := manifestFile.Close()
	if loadErr != nil {
		return fail(loadErr)
	}
	if closeErr != nil {
		return fail(fmt.Errorf("close manifest: %w", closeErr))
	}
	report, err := ops.Check(ctx, manifest, options.root)
	if err != nil {
		return fail(err)
	}
	write := ops.WriteJSON
	if options.format == "markdown" {
		write = ops.WriteMarkdown
	}
	if err := write(stdout, report); err != nil {
		return fail(fmt.Errorf("write report: %w", err))
	}
	switch report.Status {
	case contracts.StatusUnchanged:
		return 0
	case contracts.StatusReviewRequired:
		return 1
	default:
		return 2
	}
}

type checkOptions struct{ manifest, root, format string }

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func parseCheck(args []string) (checkOptions, bool, error) {
	options := checkOptions{format: "json"}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return options, true, nil
	}
	seen := make(map[string]bool)
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		if name != "--manifest" && name != "--root" && name != "--format" {
			return checkOptions{}, false, fmt.Errorf("unexpected argument %q; use --help", args[i])
		}
		if seen[name] {
			return checkOptions{}, false, fmt.Errorf("duplicate option %s", name)
		}
		seen[name] = true
		if !hasValue {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return checkOptions{}, false, fmt.Errorf("%s requires a value", name)
			}
			value = args[i]
		}
		if value == "" {
			return checkOptions{}, false, fmt.Errorf("%s requires a nonempty value", name)
		}
		switch name {
		case "--manifest":
			options.manifest = value
		case "--root":
			options.root = value
		case "--format":
			options.format = value
		}
	}
	if options.manifest == "" || options.root == "" {
		return checkOptions{}, false, fmt.Errorf("check requires --manifest and --root")
	}
	if options.format != "json" && options.format != "markdown" {
		return checkOptions{}, false, fmt.Errorf("unsupported format %q; use json or markdown", options.format)
	}
	return options, false, nil
}
