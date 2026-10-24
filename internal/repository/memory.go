package repository

import (
	"errors"
	"sync"
	"threatinfo/internal/domain"
)

var (
	ErrNotFound      = errors.New("Угрозу не найдена")
	ErrAlreadyExists = errors.New("Угроза уже существует")
)

type MemoryRepository struct {
	mu      sync.RWMutex
	threats map[string]domain.Threat
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		threats: make(map[string]domain.Threat),
	}
}

func (r *MemoryRepository) Create(threat domain.Threat) (domain.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.threats[threat.MD5]; exists {
		return domain.Threat{}, ErrAlreadyExists
	}

	r.threats[threat.MD5] = cloneThreat(threat)
	return cloneThreat(threat), nil
}

func (r *MemoryRepository) Get(md5 string) (domain.Threat, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	threat, exists := r.threats[md5]
	if !exists {
		return domain.Threat{}, ErrNotFound
	}

	return cloneThreat(threat), nil
}

func (r *MemoryRepository) Update(threat domain.Threat) (domain.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.threats[threat.MD5]; !exists {
		return domain.Threat{}, ErrNotFound
	}

	r.threats[threat.MD5] = cloneThreat(threat)
	return cloneThreat(threat), nil
}

// Функция для клонирования структуры Threat, чтобы избежать проблем с указателями на время
func cloneThreat(threat domain.Threat) domain.Threat {
	if threat.DetectedAt != nil {
		detectedAt := *threat.DetectedAt
		threat.DetectedAt = &detectedAt
	}
	return threat
}
