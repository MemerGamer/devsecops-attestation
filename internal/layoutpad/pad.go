// Package layoutpad holds dead code that only moves the linked layout of the
// gate binary for the EXP-1 Part T layout variants (PhD repository,
// experiments/val01-protocol-validation). Nothing calls padding.
package layoutpad

import "runtime"

// Sink holds the function value of padding so that the linker keeps it.
var Sink = padding

// init reads Sink once, which makes Sink and padding reachable for the linker;
// padding itself is never called. cmd/gate imports this package for this effect.
func init() {
	runtime.KeepAlive(Sink)
}
