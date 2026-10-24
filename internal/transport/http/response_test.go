package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"threatinfo/internal/repository"
	"threatinfo/internal/service"
)

func TestWriteServiceError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"validation", fmt.Errorf("context: %w", service.ErrValidation), 400},
		{"not_found", fmt.Errorf("context: %w", repository.ErrNotFound), 404},
		{"duplicate", fmt.Errorf("context: %w", repository.ErrAlreadyExists), 409},
		{"unexpected", errors.New("secret database password"), 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeServiceError(w, tc.err)
			if w.Code != tc.status {
				t.Fatalf("status=%d, want %d", w.Code, tc.status)
			}
			var body ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Message == "" || body.Details == "" {
				t.Fatalf("invalid error response: %s", w.Body.String())
			}
			if tc.status == 500 && strings.Contains(w.Body.String(), "secret") {
				t.Fatal("internal error leaked")
			}
		})
	}
}

func TestWriteJSONSerializationFailure(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, make(chan int))
	if w.Code != 500 {
		t.Fatalf("status=%d, want 500", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" || !json.Valid(w.Body.Bytes()) {
		t.Fatalf("invalid fallback: %s", w.Body.String())
	}
}
