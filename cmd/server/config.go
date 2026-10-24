package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func loadHTTPAddr(envFile string) (string, error) {
	if err := godotenv.Load(envFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("загрузка .env: %w", err)
	}

	if addr := os.Getenv("HTTP_ADDR"); addr != "" {
		return addr, nil
	}
	return ":8080", nil
}
