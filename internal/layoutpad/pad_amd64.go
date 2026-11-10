//go:build amd64

package layoutpad

// padding is 9999 single-byte NOPs followed by RET (pad_amd64.s).
func padding()
