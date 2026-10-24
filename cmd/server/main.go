package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"threatinfo/internal/repository"
	"threatinfo/internal/service"
	transport "threatinfo/internal/transport/http"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}

func run() error {
	addr, err := loadHTTPAddr(".env")
	if err != nil {
		return err
	}

	repo := repository.NewMemoryRepository()
	threatService := service.NewThreatService(repo)
	handler := transport.NewHandler(threatService)

	server := &http.Server{
		Addr:              addr,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("Сервер запускается на %s", server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-ctx.Done():
		stop()
		log.Print("Завершение работы сервера")
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		if closeErr := server.Close(); closeErr != nil {
			log.Printf("Ошибка принудительного закрытия: %v", closeErr)
		}
		return err
	}

	if err := <-serverErrors; !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
