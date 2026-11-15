//go:build !linux

package evidence

import (
	"context"
	"fmt"
	"os"

	"github.com/firmdura/triageguard/internal/contracts"
)

// New reports that collection is supported only on Linux. Other hosts should
// use the documented pinned Linux container; no weaker fallback is attempted.
func New(string) (*Collector, error) {
	return nil, fmt.Errorf("evidence collection requires Linux; use the documented Linux container")
}

func openBeneath(context.Context, *os.File, string) (*os.File, contracts.ReasonCode, error) {
	return nil, contracts.ReasonEvidenceUnreadable, nil
}
