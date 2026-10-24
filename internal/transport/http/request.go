package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"threatinfo/internal/domain"
)

type requestString struct {
	Value   string
	Present bool
}

func (s *requestString) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("Null значение недопустимо")
	}

	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	s.Value = value
	s.Present = true
	return nil
}

type ThreatCreateRequest struct {
	MD5         requestString `json:"md5"`
	Name        requestString `json:"name"`
	Type        requestString `json:"type"`
	Severity    requestString `json:"severity"`
	Description requestString `json:"description"`
	DetectedAt  requestString `json:"detected_at"`
}

type ThreatUpdateRequest struct {
	Name        requestString `json:"name"`
	Type        requestString `json:"type"`
	Severity    requestString `json:"severity"`
	Description requestString `json:"description"`
	DetectedAt  requestString `json:"detected_at"`
}

func decodeJSON[T any](body io.Reader) (T, error) {
	var zero T
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()

	var request *T
	if err := decoder.Decode(&request); err != nil {
		return zero, err
	}
	if request == nil {
		return zero, errors.New("тело запроса должно быть JSON-объектом")
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return zero, errors.New("после JSON-объекта не должно быть дополнительных данных")
	}

	return *request, nil
}

func threatFromFields(name, threatType, severity, description, detectedAt requestString) (domain.Threat, error) {
	if severity.Present && severity.Value == "" {
		return domain.Threat{}, errors.New("severity не должен быть пустым")
	}

	threat := domain.Threat{
		Name:        name.Value,
		Type:        domain.ThreatType(threatType.Value),
		Severity:    domain.Severity(severity.Value),
		Description: description.Value,
	}
	if detectedAt.Present {
		parsed, err := time.Parse(time.RFC3339, detectedAt.Value)
		if err != nil {
			return domain.Threat{}, errors.New("detected_at должен быть датой в формате RFC3339")
		}
		threat.DetectedAt = &parsed
	}
	return threat, nil
}

func (r ThreatCreateRequest) toDomain() (domain.Threat, error) {
	threat, err := threatFromFields(r.Name, r.Type, r.Severity, r.Description, r.DetectedAt)
	if err != nil {
		return domain.Threat{}, err
	}
	threat.MD5 = r.MD5.Value
	return threat, nil
}

func (r ThreatUpdateRequest) toDomain() (domain.Threat, error) {
	return threatFromFields(r.Name, r.Type, r.Severity, r.Description, r.DetectedAt)
}
