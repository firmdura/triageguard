package triageguard

import (
	"context"
	"fmt"

	"github.com/firmdura/triageguard/internal/contracts"
	"github.com/firmdura/triageguard/internal/evaluate"
	"github.com/firmdura/triageguard/internal/evidence"
)

// Check validates manifest and rechecks all its assumptions beneath root on
// Linux. It opens inputs read-only and closes its own root handle before return.
// Inputs must remain quiescent, and callers must not mutate manifest during use.
// Drift and unavailable evidence are preserved in the report, not returned as
// errors. Invalid manifests, root setup/cleanup failures, nil contexts, and
// context cancellation/deadlines return a zero Report and an error. Check never
// exits the process or establishes CVE applicability, remediation, or security.
func Check(ctx context.Context, manifest Manifest, root string) (report Report, err error) {
	if err := contracts.ValidateManifest(manifest); err != nil {
		return Report{}, err
	}
	if ctx == nil {
		return Report{}, fmt.Errorf("check context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	collector, err := evidence.New(root)
	if err != nil {
		return Report{}, err
	}
	defer func() {
		if closeErr := collector.Close(); closeErr != nil && err == nil {
			report, err = Report{}, fmt.Errorf("close evidence root: %w", closeErr)
		}
	}()
	return evaluate.Evaluate(ctx, manifest, collector)
}
