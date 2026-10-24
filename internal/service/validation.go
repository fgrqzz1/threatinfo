package service

import (
	"errors"
	"fmt"
	"strings"
	"threatinfo/internal/domain"
)

var ErrValidation = errors.New("Ошибка валидации")

func normlizeMD5(md5 string) (string, error) {
	if len(md5) != 32 {
		return "", ErrValidation
	}

	for i := 0; i < len(md5); i++ {
		c := md5[i]

		if !((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F')) {
			return "", ErrValidation
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

	// if strings.TrimSpace(threat.Description) == "" {
	// 	return fmt.Errorf("%w: Описание не должно быть пустым", ErrValidation)
	// }

	return nil
}
