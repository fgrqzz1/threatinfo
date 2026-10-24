package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
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

	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return zero, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return zero, err
	}
	if fields == nil {
		return zero, errors.New("тело запроса должно быть JSON-объектом")
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return zero, errors.New("после JSON-объекта не должно быть дополнительных данных")
	}

	// encoding/json also accepts case-insensitive matches. Check exact JSON
	// tags first so that unknown keys are rejected as specified by OpenAPI.
	requestType := reflect.TypeFor[T]()
	allowed := make(map[string]bool, requestType.NumField())
	for i := 0; i < requestType.NumField(); i++ {
		allowed[requestType.Field(i).Tag.Get("json")] = true
	}
	for key := range fields {
		if !allowed[key] {
			return zero, fmt.Errorf("неизвестное поле: %s", key)
		}
	}

	var request T
	if err := json.Unmarshal(raw, &request); err != nil {
		return zero, err
	}
	return request, nil
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
