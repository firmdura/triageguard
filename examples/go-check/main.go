// Command go-check demonstrates the public API from an external Go module.
// It checks declared assumptions, not CVE applicability or remediation.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/firmdura/triageguard/pkg/triageguard"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) != 3 || (args[2] != "json" && args[2] != "markdown") {
		fmt.Fprintln(os.Stderr, "usage: library-check MANIFEST EVIDENCE_ROOT json|markdown")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	file, err := os.Open(args[0])
	if err != nil {
		return fail(err)
	}
	manifest, loadErr := triageguard.LoadManifest(file)
	closeErr := file.Close()
	if loadErr != nil {
		return fail(loadErr)
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	// A changed or unavailable assumption is a report result. Setup failures,
	// invalid manifests, and cancellation are errors that abort the check.
	report, err := triageguard.Check(context.Background(), manifest, args[1])
	if err != nil {
		return fail(err)
	}
	write := triageguard.WriteJSON
	if args[2] == "markdown" {
		write = triageguard.WriteMarkdown
	}
	if err := write(os.Stdout, report); err != nil {
		return fail(err)
	}
	switch report.Status {
	case triageguard.StatusUnchanged:
		return 0
	case triageguard.StatusReviewRequired:
		return 1
	default:
		return 2
	}
}
