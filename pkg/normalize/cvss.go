package normalize

import (
	"fmt"
	"math"
	"strings"
)

// cvssBaseScore computes the CVSS v3.0/v3.1 base score from a vector string
// such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", following the
// official base score formula published by FIRST
// (https://www.first.org/cvss/v3.1/specification-document, section 7.1).
//
// It is shared by any adapter that consumes CVSS-scored advisories (at the
// time of writing: cargo-audit and mix_audit) so the formula is implemented
// once and tested against known reference vectors.
func cvssBaseScore(vector string) (float64, error) {
	metrics, err := parseCVSSVector(vector)
	if err != nil {
		return 0, fmt.Errorf("parsing CVSS vector %q: %w", vector, err)
	}

	av, err := cvssValue(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if err != nil {
		return 0, err
	}
	ac, err := cvssValue(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if err != nil {
		return 0, err
	}
	ui, err := cvssValue(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if err != nil {
		return 0, err
	}
	c, err := cvssValue(metrics, "C", map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if err != nil {
		return 0, err
	}
	i, err := cvssValue(metrics, "I", map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if err != nil {
		return 0, err
	}
	a, err := cvssValue(metrics, "A", map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if err != nil {
		return 0, err
	}

	scope, ok := metrics["S"]
	if !ok {
		return 0, fmt.Errorf("CVSS vector missing required metric %q", "S")
	}
	if scope != "U" && scope != "C" {
		return 0, fmt.Errorf("CVSS vector has unrecognized value %q for metric %q", scope, "S")
	}
	scopeChanged := scope == "C"

	var pr float64
	switch scope {
	case "C":
		pr, err = cvssValue(metrics, "PR", map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5})
	default:
		pr, err = cvssValue(metrics, "PR", map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27})
	}
	if err != nil {
		return 0, err
	}

	iss := 1 - (1-c)*(1-i)*(1-a)

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return 0, nil
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scopeChanged {
		base = roundUp(math.Min(1.08*(impact+exploitability), 10))
	} else {
		base = roundUp(math.Min(impact+exploitability, 10))
	}

	return base, nil
}

// parseCVSSVector splits a CVSS vector string into its metric map, ignoring
// the leading "CVSS:3.x" version prefix if present.
func parseCVSSVector(vector string) (map[string]string, error) {
	parts := strings.Split(vector, "/")
	metrics := make(map[string]string, len(parts))

	for _, part := range parts {
		if strings.HasPrefix(part, "CVSS:") {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("malformed CVSS metric segment %q", part)
		}
		metrics[kv[0]] = kv[1]
	}

	if len(metrics) == 0 {
		return nil, fmt.Errorf("empty CVSS vector")
	}
	return metrics, nil
}

// cvssValue looks up metric key in metrics and translates its value using
// values, returning an error if the metric is missing or its value is not
// one of the recognized levels.
func cvssValue(metrics map[string]string, key string, values map[string]float64) (float64, error) {
	raw, ok := metrics[key]
	if !ok {
		return 0, fmt.Errorf("CVSS vector missing required metric %q", key)
	}
	v, ok := values[raw]
	if !ok {
		return 0, fmt.Errorf("CVSS vector has unrecognized value %q for metric %q", raw, key)
	}
	return v, nil
}

// roundUp implements the CVSS spec's "Round up" function: rounds x to the
// nearest value with one decimal place, rounding up on ties, per the
// reference algorithm in the CVSS v3.1 specification appendix.
func roundUp(x float64) float64 {
	intInput := math.Round(x * 100000)
	if math.Mod(intInput, 10000) == 0 {
		return intInput / 100000
	}
	return (math.Floor(intInput/10000) + 1) / 10
}
