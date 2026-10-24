package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHTTPAddr(t *testing.T) {
	for _, tc := range []struct {
		name, file, env, want            string
		fileExists, envExists, wantError bool
	}{
		{name: "default_without_file", want: ":8080"},
		{name: "dotenv", fileExists: true, file: "# local settings\nHTTP_ADDR='127.0.0.1:9090'\n", want: "127.0.0.1:9090"},
		{name: "environment_overrides_file", fileExists: true, file: "HTTP_ADDR=:9090\n", envExists: true, env: ":9091", want: ":9091"},
		{name: "environment_without_file", envExists: true, env: ":9092", want: ":9092"},
		{name: "empty_file", fileExists: true, want: ":8080"},
		{name: "empty_value", fileExists: true, file: "HTTP_ADDR=\n", want: ":8080"},
		{name: "empty_environment_takes_precedence", fileExists: true, file: "HTTP_ADDR=:9090\n", envExists: true, want: ":8080"},
		{name: "malformed_file", fileExists: true, file: "HTTP_ADDR=\"unterminated\n", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HTTP_ADDR", tc.env)
			if !tc.envExists {
				if err := os.Unsetenv("HTTP_ADDR"); err != nil {
					t.Fatal(err)
				}
			}
			filename := filepath.Join(t.TempDir(), ".env")
			if tc.fileExists {
				if err := os.WriteFile(filename, []byte(tc.file), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := loadHTTPAddr(filename)
			if tc.wantError {
				if err == nil {
					t.Fatal("malformed .env was accepted")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got (%q, %v), want (%q, nil)", got, err, tc.want)
			}
		})
	}
}
