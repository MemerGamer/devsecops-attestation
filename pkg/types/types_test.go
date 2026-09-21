package types

import "testing"

func TestValidateCheckType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"sast constant", "sast", false},
		{"sca constant", "sca", false},
		{"config constant", "config", false},
		{"secret constant", "secret", false},
		{"custom type dast", "dast", false},
		{"custom type license", "license", false},
		{"single letter", "a", false},
		{"digits and hyphens allowed after first char", "a1-b2", false},
		{"max length 32 chars", "abcdefghijklmnopqrstuvwxyzabcdef", false}, // 32 chars
		{"empty string", "", true},
		{"uppercase not allowed", "SAST", true},
		{"cannot start with digit", "1abc", true},
		{"space not allowed", "a b", true},
		{"too long", "abcdefghijklmnopqrstuvwxyzabcdefg", true}, // 33 chars
		{"cannot start with hyphen", "-abc", true},
		{"underscore not allowed", "a_b", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCheckType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCheckType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
