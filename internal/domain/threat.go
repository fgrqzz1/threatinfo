package domain

import "time"

type (
	ThreatType string
	Severity   string
)

const (
	ThreatTypeTrojan     ThreatType = "trojan"
	ThreatTypeWorm       ThreatType = "worm"
	ThreatTypeRansomware ThreatType = "ransomware"
	ThreatTypeBackdoor   ThreatType = "backdoor"
	ThreatTypeOther      ThreatType = "other"
)

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Threat struct {
	MD5         string
	Name        string
	Type        ThreatType
	Severity    Severity
	Description string
	DetectedAt  *time.Time
}
