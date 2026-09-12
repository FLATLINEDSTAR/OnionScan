package model

import (
	"testing"
)

func TestValidateOnion_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "expyuz5wqqfdgah56trgahukbgmykuenbgjgekfdgah56trgahukbgmy.onion",
			expected: "expyuz5wqqfdgah56trgahukbgmykuenbgjgekfdgah56trgahukbgmy.onion",
		},
		{
			input:    "http://expyuz5wqqfdgah56trgahukbgmykuenbgjgekfdgah56trgahukbgmy.onion/",
			expected: "expyuz5wqqfdgah56trgahukbgmykuenbgjgekfdgah56trgahukbgmy.onion",
		},
		{
			input:    "HTTPS://EXPYUZ5WQQFDGAH56TRGAHUKBGMYKUENBGJGEKFDGAH56TRGAHUKBGMY.ONION:8080///",
			expected: "expyuz5wqqfdgah56trgahukbgmykuenbgjgekfdgah56trgahukbgmy.onion:8080",
		},
		{
			input:    "sub.example.onion",
			expected: "sub.example.onion",
		},
		{
			input:    "test.onion",
			expected: "test.onion",
		},
		{
			input:    "127.0.0.1:45678",
			expected: "127.0.0.1:45678",
		},
		{
			input:    "localhost:8080",
			expected: "localhost:8080",
		},
	}

	for _, tc := range tests {
		got, err := ValidateOnion(tc.input)
		if err != nil {
			t.Errorf("ValidateOnion(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.expected {
			t.Errorf("ValidateOnion(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestValidateOnion_Invalid(t *testing.T) {
	tests := []string{
		"",
		"   ",
		"http://",
		"https:///",
		"../target.onion",
		"..",
		"../../etc/passwd",
		"target.onion/../escape",
		"target.onion\\escape",
		"target.onion/path",
		"google.com",
		"https://evil.org",
		"target.onion.com",
		"target..onion",
		"-leadinghyphen.onion",
		"trailinghyphen-.onion",
		"target.onion:99999",
		"target.onion:0",
		"target.onion:invalidport",
		"target.onion\x00evil",
	}

	for _, input := range tests {
		got, err := ValidateOnion(input)
		if err == nil {
			t.Errorf("ValidateOnion(%q) expected error, got: %q", input, got)
		}
	}
}
