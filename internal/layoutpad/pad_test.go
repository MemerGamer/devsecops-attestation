package layoutpad

import "testing"

func TestSinkIsKept(t *testing.T) {
	if Sink == nil {
		t.Fatal("Sink must reference padding")
	}
}
