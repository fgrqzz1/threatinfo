package http

import (
	"encoding/json"
	"log"
	"net/http"
)

type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	body, err := json.Marshal(data)
	if err != nil {
		log.Printf("Ошибка сериализации ответа: %v", err)

		status = http.StatusInternalServerError
		body = []byte(`{"message":"Ошибка сервера","details":"Произошла неожиданная ошибка"}`)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(body); err != nil {
		log.Printf("Ошибка записи ответа: %v", err)
	}
}
