package service

import "threatinfo/internal/domain"

type ThreatRepository interface {
	Create(threat domain.Threat) (domain.Threat, error)
	Get(md5 string) (domain.Threat, error)
	Update(threat domain.Threat) (domain.Threat, error)
}

type ThreatService struct {
	repo ThreatRepository
}

func NewThreatService(repo ThreatRepository) *ThreatService {
	return &ThreatService{
		repo: repo,
	}
}

func (s *ThreatService) Get(md5 string) (domain.Threat, error) {
	normalizedMD5, err := normlizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repo.Get(normalizedMD5)
}

func (s *ThreatService) Create(threat domain.Threat) (domain.Threat, error) {
	normalizedMD5, err := normlizeMD5(threat.MD5)
	if err != nil {
		return domain.Threat{}, err
	}

	if err := validateThreat(threat); err != nil {
		return domain.Threat{}, err
	}

	threat.MD5 = normalizedMD5
	return s.repo.Create(threat)
}

func (s *ThreatService) Update(md5 string, threat domain.Threat) (domain.Threat, error) {
	normalizedMD5, err := normlizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}

	if err := validateThreat(threat); err != nil {
		return domain.Threat{}, err
	}

	threat.MD5 = normalizedMD5
	return s.repo.Update(threat)
}
