package http

import (
	"time"

	"threatinfo/internal/domain"
)

type ThreatResponse struct {
	MD5         string            `json:"md5"`
	Name        string            `json:"name"`
	Type        domain.ThreatType `json:"type"`
	Severity    domain.Severity   `json:"severity,omitempty"`
	Description string            `json:"description,omitempty"`
	DetectedAt  *time.Time        `json:"detected_at,omitempty"`
}

func newThreatResponse(threat domain.Threat) ThreatResponse {
	return ThreatResponse{
		MD5:         threat.MD5,
		Name:        threat.Name,
		Type:        threat.Type,
		Severity:    threat.Severity,
		Description: threat.Description,
		DetectedAt:  threat.DetectedAt,
	}
}
