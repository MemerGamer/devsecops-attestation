// Package policies embeds the canonical Rego deploy gate policy so it can be
// compiled into the gate binary as a single source of truth. Other repositories
// that vendor this module reuse this file instead of copying policy text.
package policies

import _ "embed"

// Deploy is the source of deploy.rego, the canonical deploy gate policy.
//
//go:embed deploy.rego
var Deploy string
