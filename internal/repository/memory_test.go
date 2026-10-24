package repository_test

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"threatinfo/internal/domain"
	"threatinfo/internal/repository"
)

func TestMemoryRepositoryLifecycle(t *testing.T) {
	r := repository.NewMemoryRepository()
	v := domain.Threat{MD5: "abcdef0123456789abcdef0123456789", Name: "original", Type: domain.ThreatTypeTrojan, Severity: domain.SeverityHigh, Description: "old"}
	if _, err := r.Get(v.MD5); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Get missing: %v", err)
	}
	if _, err := r.Update(v); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Update missing: %v", err)
	}
	if _, err := r.Get(v.MD5); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("Update created a missing record")
	}
	created, err := r.Create(v)
	if err != nil || !reflect.DeepEqual(created, v) {
		t.Fatalf("Create: %+v %v", created, err)
	}
	duplicate := v
	duplicate.Name = "duplicate"
	if _, err := r.Create(duplicate); !errors.Is(err, repository.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := r.Get(v.MD5)
	if err != nil || !reflect.DeepEqual(got, v) {
		t.Fatalf("Get after duplicate: %+v %v", got, err)
	}
	replacement := domain.Threat{MD5: v.MD5, Name: "updated", Type: domain.ThreatTypeWorm}
	if _, err := r.Update(replacement); err != nil {
		t.Fatal(err)
	}
	got, err = r.Get(v.MD5)
	if err != nil || !reflect.DeepEqual(got, replacement) {
		t.Fatalf("replacement: %+v %v", got, err)
	}
	if _, err := repository.NewMemoryRepository().Get(v.MD5); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("repositories share state")
	}
}

func TestMemoryRepositoryCopiesTimestamp(t *testing.T) {
	r := repository.NewMemoryRepository()
	original := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	date := original
	v := domain.Threat{MD5: "abcdef0123456789abcdef0123456789", DetectedAt: &date}
	created, err := r.Create(v)
	if err != nil {
		t.Fatal(err)
	}
	date = date.Add(time.Hour)
	*created.DetectedAt = created.DetectedAt.Add(2 * time.Hour)
	got, err := r.Get(v.MD5)
	if err != nil || !got.DetectedAt.Equal(original) {
		t.Fatalf("Create exposed timestamp: %+v %v", got, err)
	}
	*got.DetectedAt = got.DetectedAt.Add(3 * time.Hour)
	again, err := r.Get(v.MD5)
	if err != nil || !again.DetectedAt.Equal(original) {
		t.Fatalf("Get exposed timestamp: %+v %v", again, err)
	}
	updated, err := r.Update(v)
	if err != nil {
		t.Fatal(err)
	}
	want := date
	date = date.Add(time.Hour)
	*updated.DetectedAt = updated.DetectedAt.Add(time.Hour)
	again, err = r.Get(v.MD5)
	if err != nil || !again.DetectedAt.Equal(want) {
		t.Fatalf("Update exposed timestamp: %+v %v", again, err)
	}
}

func TestMemoryRepositoryConcurrentAccess(t *testing.T) {
	r := repository.NewMemoryRepository()
	v := domain.Threat{MD5: "abcdef0123456789abcdef0123456789", Name: "sample", Type: domain.ThreatTypeOther}
	const workers = 32
	results := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, err := r.Create(v); results <- err }()
	}
	close(start)
	wg.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		} else if !errors.Is(err, repository.ErrAlreadyExists) {
			t.Errorf("Create: %v", err)
		}
	}
	if created != 1 {
		t.Fatalf("successful creates = %d, want 1", created)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := r.Get(v.MD5); err != nil {
					t.Error(err)
					return
				}
				if _, err := r.Update(v); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
