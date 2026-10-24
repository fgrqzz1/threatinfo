package service

import (
	"errors"
	"strings"
	"testing"

	"threatinfo/internal/domain"
	"threatinfo/internal/repository"
)

type repositoryStub struct {
	calls  int
	key    string
	threat domain.Threat
	err    error
}

func (r *repositoryStub) Create(v domain.Threat) (domain.Threat, error) {
	r.calls++
	r.threat = v
	return v, r.err
}
func (r *repositoryStub) Get(key string) (domain.Threat, error) {
	r.calls++
	r.key = key
	return r.threat, r.err
}
func (r *repositoryStub) Update(v domain.Threat) (domain.Threat, error) {
	r.calls++
	r.threat = v
	return v, r.err
}

func TestServiceNormalizesKeys(t *testing.T) {
	const hash = "abcdef0123456789abcdef0123456789"
	input := domain.Threat{MD5: strings.ToUpper(hash), Name: "sample", Type: domain.ThreatTypeWorm}
	r := &repositoryStub{}
	s := NewThreatService(r)
	created, err := s.Create(input)
	if err != nil || created.MD5 != hash || r.threat.MD5 != hash {
		t.Fatalf("Create: %+v, %v", created, err)
	}
	if input.MD5 != strings.ToUpper(hash) {
		t.Fatal("Create mutated caller's value")
	}
	if _, err := s.Get(strings.ToUpper(hash)); err != nil || r.key != hash {
		t.Fatalf("Get: key=%q err=%v", r.key, err)
	}
	input.MD5 = "body must not determine the update key"
	updated, err := s.Update(strings.ToUpper(hash), input)
	if err != nil || updated.MD5 != hash || r.threat.MD5 != hash {
		t.Fatalf("Update: %+v, %v", updated, err)
	}
}

func TestServiceRejectsInvalidInputBeforeRepository(t *testing.T) {
	const hash = "abcdef0123456789abcdef0123456789"
	for _, tc := range []struct {
		name string
		call func(*ThreatService) error
	}{
		{"get_hash", func(s *ThreatService) error { _, err := s.Get("bad"); return err }},
		{"create_hash", func(s *ThreatService) error {
			_, err := s.Create(domain.Threat{MD5: "bad", Name: "x", Type: domain.ThreatTypeOther})
			return err
		}},
		{"create_fields", func(s *ThreatService) error { _, err := s.Create(domain.Threat{MD5: hash}); return err }},
		{"update_hash", func(s *ThreatService) error {
			_, err := s.Update("bad", domain.Threat{Name: "x", Type: domain.ThreatTypeOther})
			return err
		}},
		{"update_fields", func(s *ThreatService) error { _, err := s.Update(hash, domain.Threat{}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &repositoryStub{}
			if err := tc.call(NewThreatService(r)); !errors.Is(err, ErrValidation) {
				t.Fatalf("got %v, want ErrValidation", err)
			}
			if r.calls != 0 {
				t.Fatalf("repository called %d times", r.calls)
			}
		})
	}
}

func TestServicePreservesRepositoryErrors(t *testing.T) {
	v := domain.Threat{MD5: "abcdef0123456789abcdef0123456789", Name: "x", Type: domain.ThreatTypeOther}
	for _, want := range []error{repository.ErrNotFound, repository.ErrAlreadyExists, errors.New("storage failure")} {
		r := &repositoryStub{err: want}
		s := NewThreatService(r)
		_, createErr := s.Create(v)
		_, getErr := s.Get(v.MD5)
		_, updateErr := s.Update(v.MD5, v)
		for _, got := range []error{createErr, getErr, updateErr} {
			if !errors.Is(got, want) {
				t.Errorf("got %v, want %v", got, want)
			}
		}
	}
}
