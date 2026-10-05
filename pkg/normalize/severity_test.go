package normalize

import "testing"

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityToTypesSeverity(t *testing.T) {
	if got := SeverityHigh.ToTypesSeverity(); got != "high" {
		t.Errorf("ToTypesSeverity() = %q, want %q", got, "high")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input   string
		want    Severity
		wantErr bool
	}{
		{"info", SeverityInfo, false},
		{"INFO", SeverityInfo, false},
		{"informational", SeverityInfo, false},
		{" low ", SeverityLow, false},
		{"medium", SeverityMedium, false},
		{"moderate", SeverityMedium, false},
		{"warning", SeverityMedium, false},
		{"high", SeverityHigh, false},
		{"error", SeverityHigh, false},
		{"critical", SeverityCritical, false},
		{"unknown", SeverityLow, false},
		{"CRITICAL", SeverityCritical, false},
		{"nonsense", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseSeverity(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSeverity(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFromCVSS(t *testing.T) {
	tests := []struct {
		score float64
		want  Severity
	}{
		{0, SeverityInfo},
		{-1, SeverityInfo},
		{0.1, SeverityLow},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10.0, SeverityCritical},
	}
	for _, tt := range tests {
		if got := FromCVSS(tt.score); got != tt.want {
			t.Errorf("FromCVSS(%v) = %v, want %v", tt.score, got, tt.want)
		}
	}
}
