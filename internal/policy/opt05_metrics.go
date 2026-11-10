package policy

import (
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/metrics"
	"os"
	"time"
)

// Each Evaluate call appends one record. The same collector accumulates both
// allow and deny queries; timers are disjoint phases, not cumulative stacks.
// Only elapsed time and numeric metrics are written, never policy or input data.
func startOpt05Metrics() (metrics.Metrics, func() error, error) {
	path := os.Getenv("OPT05_OPA_METRICS")
	if path == "" {
		return nil, func() error { return nil }, nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("opening opt05 metrics: %w", err)
	}
	m := metrics.New()
	start := time.Now()
	return m, func() error {
		elapsed := time.Since(start).Nanoseconds()
		err := json.NewEncoder(file).Encode(struct {
			ElapsedNS int64          `json:"elapsed_ns"`
			Timers    map[string]any `json:"timers"`
		}{elapsed, m.All()})
		closeErr := file.Close()
		if err != nil {
			return fmt.Errorf("writing opt05 metrics: %w", err)
		}
		if closeErr != nil {
			return fmt.Errorf("closing opt05 metrics: %w", closeErr)
		}
		return nil
	}, nil
}
