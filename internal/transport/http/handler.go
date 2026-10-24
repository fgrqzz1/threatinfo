package http

import (
	"errors"
	"log"
	"net/http"

	"threatinfo/internal/domain"
	"threatinfo/internal/repository"
	"threatinfo/internal/service"
)

type ThreatService interface {
	Create(domain.Threat) (domain.Threat, error)
	Get(string) (domain.Threat, error)
	Update(string, domain.Threat) (domain.Threat, error)
}

type Handler struct {
	service ThreatService
}

func NewHandler(service ThreatService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /info", h.create)
	mux.HandleFunc("GET /info/{md5}", h.get)
	mux.HandleFunc("PUT /info/{md5}", h.update)

	// Path-only handlers keep routing errors in the same JSON format.
	mux.HandleFunc("/info", methodNotAllowed("POST"))
	mux.HandleFunc("/info/{md5}", methodNotAllowed("GET, HEAD, PUT"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Message: "Маршрут не найден",
			Details: "Запрошенный путь не поддерживается",
		})
	})
	return mux
}

func methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{
			Message: "Метод не поддерживается",
			Details: "Допустимые методы: " + allow,
		})
	}
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[ThreatCreateRequest](r.Body)
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	threat, err := request.toDomain()
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	created, err := h.service.Create(threat)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, newThreatResponse(created))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	threat, err := h.service.Get(r.PathValue("md5"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newThreatResponse(threat))
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[ThreatUpdateRequest](r.Body)
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	threat, err := request.toDomain()
	if err != nil {
		writeBadRequest(w, err)
		return
	}
	updated, err := h.service.Update(r.PathValue("md5"), threat)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newThreatResponse(updated))
}

func writeBadRequest(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, ErrorResponse{
		Message: "Некорректный запрос",
		Details: err.Error(),
	})
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrValidation):
		writeBadRequest(w, err)
	case errors.Is(err, repository.ErrNotFound):
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Message: "Угроза не найдена",
			Details: "Запись с указанным MD5 отсутствует",
		})
	case errors.Is(err, repository.ErrAlreadyExists):
		writeJSON(w, http.StatusConflict, ErrorResponse{
			Message: "Угроза уже существует",
			Details: "Запись с указанным MD5 уже существует",
		})
	default:
		log.Printf("Ошибка сервиса: %v", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Message: "Ошибка сервера",
			Details: "Произошла неожиданная ошибка",
		})
	}
}
