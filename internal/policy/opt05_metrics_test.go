package policy

import (
	"context"
	"encoding/json"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOpt05Metrics(t *testing.T) {
	e := NewEvaluator("")
	input := types.PolicyInput{}
	t.Setenv("OPT05_OPA_METRICS", "")
	before, err := e.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	t.Setenv("OPT05_OPA_METRICS", path)
	after, err := e.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	// Reason order is unspecified. This empty fixture has one denial reason.
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("decision changed: %#v %#v", before, after)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var row struct {
		Elapsed int64            `json:"elapsed_ns"`
		Timers  map[string]int64 `json:"timers"`
	}
	if err := json.NewDecoder(file).Decode(&row); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"timer_rego_module_parse_ns", "timer_rego_module_compile_ns", "timer_rego_query_compile_ns", "timer_rego_query_eval_ns", "timer_rego_query_parse_ns"} {
		if row.Timers[key] <= 0 {
			t.Errorf("missing timer %s", key)
		}
	}
	if row.Elapsed <= 0 {
		t.Fatal("missing elapsed time")
	}
	t.Setenv("OPT05_OPA_METRICS", filepath.Join(path, "invalid"))
	if _, err := e.Evaluate(context.Background(), input); err == nil {
		t.Fatal("ignored metrics write failure")
	}
}
