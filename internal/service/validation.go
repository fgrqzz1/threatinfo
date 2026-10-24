package service

import (
	"errors"
	"fmt"
	"strings"

	"threatinfo/internal/domain"
)

var ErrValidation = errors.New("Ошибка валидации")

func normalizeMD5(md5 string) (string, error) {
	if len(md5) != 32 {
		return "", fmt.Errorf("%w: MD5 должен содержать 32 шестнадцатеричных ASCII-символа", ErrValidation)
	}

	for i := 0; i < len(md5); i++ {
		c := md5[i]

		if !((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F')) {
			return "", fmt.Errorf("%w: MD5 должен содержать 32 шестнадцатеричных ASCII-символа", ErrValidation)
		}
	}
	return strings.ToLower(md5), nil
}

func validateThreat(threat domain.Threat) error {
	if strings.TrimSpace(threat.Name) == "" {
		return fmt.Errorf("%w: Имя не должно быть пустым", ErrValidation)
	}

	switch threat.Type {
	case domain.ThreatTypeTrojan,
		domain.ThreatTypeWorm,
		domain.ThreatTypeRansomware,
		domain.ThreatTypeBackdoor,
		domain.ThreatTypeOther:
	default:
		return fmt.Errorf("%w: Неверный тип угрозы", ErrValidation)
	}

	switch threat.Severity {
	case "",
		domain.SeverityLow,
		domain.SeverityMedium,
		domain.SeverityHigh,
		domain.SeverityCritical:
	default:
		return fmt.Errorf("%w: Неверный уровень опасности", ErrValidation)
	}

	return nil
}
