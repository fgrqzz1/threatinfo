package service

import (
	"errors"
	"strings"
	"testing"

	"threatinfo/internal/domain"
)

func TestNormalizeMD5(t *testing.T) {
	const hash = "abcdef0123456789abcdef0123456789"
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"lowercase", hash, true},
		{"uppercase", strings.ToUpper(hash), true},
		{"empty", "", false},
		{"short", hash[:31], false},
		{"long", hash + "0", false},
		{"non_hex", "g" + hash[1:], false},
		{"space", " " + hash[1:], false},
		{"unicode", strings.Repeat("а", 16), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeMD5(tc.input)
			if tc.valid {
				if err != nil || got != hash {
					t.Fatalf("got (%q, %v), want (%q, nil)", got, err, hash)
				}
			} else if !errors.Is(err, ErrValidation) {
				t.Fatalf("got %v, want ErrValidation", err)
			}
		})
	}
}

func TestValidateThreat(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*domain.Threat)
		valid bool
	}{
		{"minimal", func(*domain.Threat) {}, true},
		{"empty_name", func(v *domain.Threat) { v.Name = "" }, false},
		{"whitespace_name", func(v *domain.Threat) { v.Name = " \t\n\u00a0" }, false},
		{"missing_type", func(v *domain.Threat) { v.Type = "" }, false},
		{"unknown_type", func(v *domain.Threat) { v.Type = "virus" }, false},
		{"unknown_severity", func(v *domain.Threat) { v.Severity = "urgent" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := domain.Threat{Name: "sample", Type: domain.ThreatTypeTrojan}
			tc.edit(&v)
			err := validateThreat(v)
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && !errors.Is(err, ErrValidation) {
				t.Fatalf("got %v, want ErrValidation", err)
			}
		})
	}
	for _, kind := range []domain.ThreatType{domain.ThreatTypeTrojan, domain.ThreatTypeWorm, domain.ThreatTypeRansomware, domain.ThreatTypeBackdoor, domain.ThreatTypeOther} {
		for _, severity := range []domain.Severity{"", domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical} {
			if err := validateThreat(domain.Threat{Name: "sample", Type: kind, Severity: severity}); err != nil {
				t.Errorf("type=%q severity=%q: %v", kind, severity, err)
			}
		}
	}
}
