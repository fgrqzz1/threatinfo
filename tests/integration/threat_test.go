package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"threatinfo/internal/repository"
	"threatinfo/internal/service"
	transport "threatinfo/internal/transport/http"
)

const testMD5 = "abcdef0123456789abcdef0123456789"

func startAPI(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(transport.NewHandler(service.NewThreatService(repository.NewMemoryRepository())).Routes())
	t.Cleanup(s.Close)
	return s
}

func requestJSON(t *testing.T, server *httptest.Server, method, path, body string, wantStatus int) map[string]json.RawMessage {
	t.Helper()
	req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := server.Client()
	client.Timeout = 5 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: status=%d, want %d; body=%s", method, path, resp.StatusCode, wantStatus, data)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q; body=%s", got, data)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %s: %v", data, err)
	}
	if result == nil {
		t.Fatal("response must be an object")
	}
	if wantStatus >= 400 {
		if len(result) != 2 {
			t.Fatalf("unexpected error fields: %s", data)
		}
		for _, field := range []string{"message", "details"} {
			var value string
			if err := json.Unmarshal(result[field], &value); err != nil || value == "" {
				t.Fatalf("invalid error field %s: %s", field, data)
			}
		}
	}
	return result
}

func TestThreatLifecycleIntegration(t *testing.T) {
	s := startAPI(t)
	path := "/info/" + testMD5
	requestJSON(t, s, "GET", path, "", 404)
	body := `{"md5":"` + strings.ToUpper(testMD5) + `","name":"sample","type":"trojan","severity":"high","description":"sample description","detected_at":"2026-10-24T12:00:00Z"}`
	created := requestJSON(t, s, "POST", "/info", body, 201)
	want := map[string]json.RawMessage{
		"md5": json.RawMessage(`"` + testMD5 + `"`), "name": json.RawMessage(`"sample"`),
		"type": json.RawMessage(`"trojan"`), "severity": json.RawMessage(`"high"`),
		"description": json.RawMessage(`"sample description"`), "detected_at": json.RawMessage(`"2026-10-24T12:00:00Z"`),
	}
	if !reflect.DeepEqual(created, want) {
		t.Fatalf("created=%s, want=%s", created, want)
	}
	got := requestJSON(t, s, "GET", "/info/"+strings.ToUpper(testMD5), "", 200)
	if !reflect.DeepEqual(got, created) {
		t.Fatal("GET differs from created threat")
	}
	requestJSON(t, s, "POST", "/info", `{"md5":"`+testMD5+`","name":"duplicate","type":"other"}`, 409)
	got = requestJSON(t, s, "GET", path, "", 200)
	if !reflect.DeepEqual(got, created) {
		t.Fatal("duplicate changed stored threat")
	}
	updated := requestJSON(t, s, "PUT", "/info/"+strings.ToUpper(testMD5), `{"name":"updated","type":"worm"}`, 200)
	want = map[string]json.RawMessage{"md5": json.RawMessage(`"` + testMD5 + `"`), "name": json.RawMessage(`"updated"`), "type": json.RawMessage(`"worm"`)}
	if !reflect.DeepEqual(updated, want) {
		t.Fatalf("PUT did not replace optional fields: %s", updated)
	}
	got = requestJSON(t, s, "GET", path, "", 200)
	if !reflect.DeepEqual(got, updated) {
		t.Fatal("PUT result was not persisted")
	}
	// A new application instance starts with an independent empty repository.
	requestJSON(t, startAPI(t), "GET", path, "", 404)
}

func TestInvalidRequestsIntegration(t *testing.T) {
	s := startAPI(t)
	valid := `{"md5":"` + testMD5 + `","name":"sample","type":"other"}`
	for _, tc := range []struct{ name, body string }{
		{"empty", ""}, {"null_object", "null"}, {"array", "[]"}, {"scalar", "42"},
		{"malformed", `{"name":`}, {"second_object", valid + ` {}`}, {"trailing_garbage", valid + ` x`},
		{"missing_md5", `{"name":"x","type":"other"}`},
		{"missing_name", `{"md5":"` + testMD5 + `","type":"other"}`},
		{"missing_type", `{"md5":"` + testMD5 + `","name":"x"}`},
		{"invalid_md5", strings.Replace(valid, testMD5, "g"+testMD5[1:], 1)},
		{"blank_name", strings.Replace(valid, `"sample"`, `" \t\n"`, 1)},
		{"unknown_type", strings.Replace(valid, `"other"`, `"virus"`, 1)},
		{"empty_type", strings.Replace(valid, `"other"`, `""`, 1)},
		{"unknown_field", strings.TrimSuffix(valid, "}") + `,"unexpected":"x"}`},
		{"empty_severity", strings.TrimSuffix(valid, "}") + `,"severity":""}`},
		{"unknown_severity", strings.TrimSuffix(valid, "}") + `,"severity":"urgent"}`},
		{"empty_date", strings.TrimSuffix(valid, "}") + `,"detected_at":""}`},
		{"invalid_date", strings.TrimSuffix(valid, "}") + `,"detected_at":"2026-02-30T00:00:00Z"}`},
		{"date_without_zone", strings.TrimSuffix(valid, "}") + `,"detected_at":"2026-10-24T12:00:00"}`},
	} {
		t.Run(tc.name, func(t *testing.T) { requestJSON(t, s, "POST", "/info", tc.body, 400) })
	}
	for _, field := range []string{"md5", "name", "type", "severity", "description", "detected_at"} {
		for _, value := range []string{"null", "123", "true", "[]", "{}"} {
			t.Run(field+"_"+value, func(t *testing.T) {
				fields := map[string]json.RawMessage{"md5": json.RawMessage(`"` + testMD5 + `"`), "name": json.RawMessage(`"x"`), "type": json.RawMessage(`"other"`)}
				fields[field] = json.RawMessage(value)
				body, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				requestJSON(t, s, "POST", "/info", string(body), 400)
			})
		}
	}
	requestJSON(t, s, "GET", "/info/"+testMD5, "", 404)
	requestJSON(t, s, "POST", "/info", valid+" \n\t", 201)
	before := requestJSON(t, s, "GET", "/info/"+testMD5, "", 200)
	for _, body := range []string{valid, `{"name":"changed"}`, `{"name":"changed","type":"worm","severity":""}`, `{"name":"changed","type":"worm","detected_at":null}`, `{"name":"changed","type":"worm","unknown":"x"}`} {
		requestJSON(t, s, "PUT", "/info/"+testMD5, body, 400)
	}
	after := requestJSON(t, s, "GET", "/info/"+testMD5, "", 200)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("invalid PUT changed the stored record")
	}
}

func TestPathsIntegration(t *testing.T) {
	s := startAPI(t)
	requestJSON(t, s, "GET", "/info/bad", "", 400)
	requestJSON(t, s, "PUT", "/info/bad", `{"name":"x","type":"other"}`, 400)
	requestJSON(t, s, "PUT", "/info/"+testMD5, `{"name":"x","type":"other"}`, 404)
	requestJSON(t, s, "GET", "/missing", "", 404)
	requestJSON(t, s, "DELETE", "/info/"+testMD5, "", 405)
	requestJSON(t, s, "GET", "/info", "", 405)
}
