package policy

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// oldEvaluate is a frozen copy of v0.4.2 Evaluate (two queries).
func oldEvaluate(e *Evaluator, ctx context.Context, input types.PolicyInput) (*types.GateDecision, error) {
	regoOpts := []func(*rego.Rego){rego.Module("policy.rego", e.policy), rego.Input(toMap(input))}
	if e.data != nil {
		regoOpts = append(regoOpts, rego.Store(inmem.NewFromObject(map[string]any{"config": e.data})))
	}
	allowQuery := rego.New(append([]func(*rego.Rego){rego.Query("data.devsecops.gate.allow")}, regoOpts...)...)
	denyQuery := rego.New(append([]func(*rego.Rego){rego.Query("data.devsecops.gate.deny_reasons")}, regoOpts...)...)
	allowRS, err := allowQuery.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating allow policy: %w", err)
	}
	allow := false
	if len(allowRS) > 0 && len(allowRS[0].Expressions) > 0 {
		allow, _ = allowRS[0].Expressions[0].Value.(bool)
	}
	denyRS, err := denyQuery.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating deny_reasons policy: %w", err)
	}
	var reasons []string
	if len(denyRS) > 0 && len(denyRS[0].Expressions) > 0 {
		switch set := denyRS[0].Expressions[0].Value.(type) {
		case map[string]interface{}:
			for k := range set {
				reasons = append(reasons, k)
			}
		case []interface{}:
			for _, elem := range set {
				if s, ok := elem.(string); ok {
					reasons = append(reasons, s)
				}
			}
		}
	}
	if allow && len(reasons) == 0 {
		reasons = []string{"all checks passed"}
	}
	return &types.GateDecision{Allow: allow, Reasons: reasons}, nil
}

var extraPolicies = map[string]string{
	"allow-only":    "package devsecops.gate\nimport rego.v1\nallow := true\n",
	"deny-only":     "package devsecops.gate\nimport rego.v1\ndeny_reasons contains \"no\" if true\n",
	"deny-conflict": "package devsecops.gate\nimport rego.v1\nallow := true\ndeny_reasons := [\"a\"] if true\ndeny_reasons := [\"b\"] if true\n",

	"conflict-unused-rule": "package devsecops.gate\nimport rego.v1\ndefault allow := true\nx := 1 if true\nx := 2 if true\n",
	"objset-deny":          "package devsecops.gate\nimport rego.v1\ndefault allow := false\ndeny_reasons[k] := true if { some k in [\"a\",\"b\"] }\n",
	"allow-nonbool":        "package devsecops.gate\nimport rego.v1\nallow := \"yes\"\ndeny_reasons contains \"r\" if true\n",
	"other-package":        "package other.gate\nimport rego.v1\nallow := true\n",
	"allow-conflict":       "package devsecops.gate\nimport rego.v1\nallow := true if true\nallow := false if true\n",
	"deny-mixed-types":     "package devsecops.gate\nimport rego.v1\ndefault allow := true\ndeny_reasons contains 1 if true\ndeny_reasons contains \"s\" if true\n",
	"divzero-unused":       "package devsecops.gate\nimport rego.v1\ndefault allow := true\ny := 1/0 if true\n",
	"config-echo":          "package devsecops.gate\nimport rego.v1\nallow if data.config.ok == true\ndeny_reasons contains sprintf(\"%v\", [data.config]) if true\n",
}

var checkTypes = []string{"sast", "sca", "config", "secret", "dast", "license", ""}
var sevs = []string{"info", "low", "medium", "high", "critical", "", "HIGH", "bogus"}

var nearValid bool

func randInput(r *rand.Rand) types.PolicyInput {
	if nearValid {
		return nearValidInput(r)
	}
	keys := [][]byte{{1, 2, 3}, {4, 5, 6}}
	var atts []types.Attestation
	if r.Intn(5) != 0 { // mostly the full required set
		for _, c := range []string{"sast", "sca", "config", "secret"} {
			if r.Intn(10) != 0 {
				atts = append(atts, mkAtt(r, c, keys))
			}
		}
	}
	for i := r.Intn(3); i > 0; i-- {
		atts = append(atts, mkAtt(r, checkTypes[r.Intn(len(checkTypes))], keys))
	}
	in := types.PolicyInput{Subject: types.AttestationSubject{Name: "app"}, Attestations: atts, RunAt: time.Unix(0, 0).UTC()}
	if r.Intn(2) == 0 {
		in.AuthorizedSigners = map[string]string{}
		for _, c := range []string{"sast", "sca", "config", "secret"} {
			if r.Intn(2) == 0 {
				in.AuthorizedSigners[c] = []string{"010203", "040506", "ffff"}[r.Intn(3)]
			}
		}
	}
	return in
}

func mkAtt(r *rand.Rand, c string, keys [][]byte) types.Attestation {
	var fs []types.Finding
	if r.Intn(3) == 0 {
		for i := r.Intn(3) + 1; i > 0; i-- {
			fs = append(fs, types.Finding{ID: fmt.Sprint(i), Severity: types.Severity(sevs[r.Intn(len(sevs))])})
		}
	}
	if fs == nil && r.Intn(2) == 0 {
		fs = []types.Finding{}
	}
	return types.Attestation{ID: c, Result: types.SecurityResult{CheckType: types.SecurityCheckType(c), Findings: fs, Passed: r.Intn(6) != 0},
		SignerPublicKey: keys[r.Intn(2)]}
}

func randConfig(r *rand.Rand) map[string]any {
	opts := []map[string]any{
		nil, nil, {},
		{"fail_on_severity": "critical"}, {"fail_on_severity": "low"}, {"fail_on_severity": "bogus"}, {"fail_on_severity": 4},
		{"required_checks": []any{"sast", "sca"}}, {"required_checks": "sast"}, {"required_checks": []any{}}, {"required_checks": []any{1, "x"}},
		{"zero_tolerance_checks": []any{"sast"}}, {"zero_tolerance_checks": []any{}}, {"zero_tolerance_checks": "secret"},
		{"required_checks": []any{"sast", "sca", "config", "secret", "dast"}, "fail_on_severity": "medium", "zero_tolerance_checks": []any{"secret", "dast"}},
		{"ok": true},
	}
	return opts[r.Intn(len(opts))]
}

func norm(d *types.GateDecision) (bool, []string) {
	rs := append([]string{}, d.Reasons...)
	sort.Strings(rs)
	return d.Allow, rs
}

// TestEvaluateDifferential checks decisions (reasons as an unordered set) and
// error presence, not error wording: the single query has one error context.
// The seed, policy order, input timestamps and case counts are fixed.
func TestEvaluateDifferential(t *testing.T) {
	pols := map[string]string{}
	b, err := os.ReadFile("../../policies/deploy.rego")
	if err != nil {
		t.Fatal(err)
	}
	pols["deploy"] = string(b)
	td, err := filepath.Glob("testdata/*.rego")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range td {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		pols[filepath.Base(f)] = string(b)
	}
	pols["invalid-rego"] = "package devsecops.gate\nallow := {"
	for k, v := range extraPolicies {
		pols[k] = v
	}
	r := rand.New(rand.NewSource(20261111))
	ctx := context.Background()
	names := make([]string, 0, len(pols))
	for k := range pols {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		n := 40
		if name == "deploy" {
			n = 1500
		}
		mism, errDiff, allowT, total := 0, 0, 0, 0
		for i := 0; i < n; i++ {
			in := randInput(r)
			cfg := randConfig(r)
			var opts []EvaluatorOption
			if cfg != nil {
				opts = append(opts, WithData(cfg))
			}
			e := NewEvaluator(pols[name], opts...)
			od, oerr := oldEvaluate(e, ctx, in)
			nd, nerr := e.Evaluate(ctx, in)
			total++
			if (oerr == nil) != (nerr == nil) {
				errDiff++
				if errDiff == 1 {
					t.Errorf("%s: error mismatch old=%v new=%v", name, oerr, nerr)
				}
				continue
			}
			if oerr != nil {
				if i == 0 {
					t.Logf("%s: both error: old=%.80v | new=%.80v", name, oerr, nerr)
				}
				continue
			}
			oa, or := norm(od)
			na, nr := norm(nd)
			if oa {
				allowT++
			}
			if oa != na || !reflect.DeepEqual(or, nr) {
				mism++
				if mism <= 2 {
					t.Errorf("%s: MISMATCH old=(%v %q) new=(%v %q) cfg=%v", name, oa, or, na, nr, cfg)
				}
			}
		}
		t.Logf("policy %-26s cases=%4d allow=%4d decision-mismatch=%d error-mismatch=%d", name, total, allowT, mism, errDiff)
	}
}

func nearValidInput(r *rand.Rand) types.PolicyInput {
	var atts []types.Attestation
	for _, c := range []string{"sast", "sca", "config", "secret"} {
		a := types.Attestation{ID: c, Result: types.SecurityResult{CheckType: types.SecurityCheckType(c), Findings: []types.Finding{}, Passed: true}, SignerPublicKey: []byte{1, 2, 3}}
		if r.Intn(8) == 0 {
			a.Result.Findings = []types.Finding{{ID: "f", Severity: types.Severity(sevs[r.Intn(len(sevs))])}}
		}
		if r.Intn(30) == 0 {
			a.Result.Passed = false
		}
		atts = append(atts, a)
	}
	in := types.PolicyInput{Attestations: atts}
	if r.Intn(2) == 0 {
		in.AuthorizedSigners = map[string]string{"sast": "010203", "sca": "010203", "config": "010203", "secret": "010203"}
		if r.Intn(20) == 0 {
			in.AuthorizedSigners["sca"] = "040506"
		}
	}
	return in
}

func TestEvaluateDifferentialNearValid(t *testing.T) {
	nearValid = true
	defer func() { nearValid = false }()
	TestEvaluateDifferential(t)
}
