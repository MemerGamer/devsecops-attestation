package normalize

import "testing"

func TestCvssBaseScore(t *testing.T) {
	tests := []struct {
		name    string
		vector  string
		want    float64
		wantErr bool
	}{
		{
			name:   "scope unchanged, all high impact, no privileges or interaction",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   9.8,
		},
		{
			name:   "scope unchanged, high access complexity, confidentiality only",
			vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
			want:   5.9,
		},
		{
			name:   "scope changed, user interaction required",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
			want:   9.6,
		},
		{
			name:   "missing version prefix still parses metrics",
			vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   9.8,
		},
		{
			name:    "empty vector is an error",
			vector:  "",
			wantErr: true,
		},
		{
			name:    "missing required metric is an error",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "unrecognized metric value is an error",
			vector:  "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "malformed segment is an error",
			vector:  "CVSS:3.1/AV/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "version prefix with no metrics is an error",
			vector:  "CVSS:3.1",
			wantErr: true,
		},
		{
			name:    "missing AC metric is an error",
			vector:  "CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "unrecognized AC value is an error",
			vector:  "CVSS:3.1/AV:N/AC:X/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "unrecognized UI value is an error",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:X/S:U/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "unrecognized C value is an error",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:X/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "unrecognized I value is an error",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:X/A:H",
			wantErr: true,
		},
		{
			name:    "unrecognized A value is an error",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:X",
			wantErr: true,
		},
		{
			name:    "unrecognized PR value with scope changed is an error",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:C/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "unrecognized PR value with scope unchanged is an error",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:    "unrecognized S value is an error",
			vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
			wantErr: true,
		},
		{
			name:   "scope changed with low privileges required",
			vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
			want:   9.9,
		},
		{
			name:   "all-none impact yields zero score",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			want:   0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cvssBaseScore(tt.vector)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("cvssBaseScore(%q) expected error, got score %v", tt.vector, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("cvssBaseScore(%q) unexpected error: %v", tt.vector, err)
			}
			if got != tt.want {
				t.Errorf("cvssBaseScore(%q) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}

func TestRoundUp(t *testing.T) {
	tests := []struct {
		name string
		in   float64
		want float64
	}{
		{name: "already exact to one decimal", in: 4.0, want: 4.0},
		{name: "rounds up on tie", in: 4.02, want: 4.1},
		{name: "rounds up fractional remainder", in: 4.111, want: 4.2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := roundUp(tt.in); got != tt.want {
				t.Errorf("roundUp(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
