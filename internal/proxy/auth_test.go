package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithTokenAuth(t *testing.T) {
	const token = "good-token-xyz"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := withTokenAuth(token, next)

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic " + token, http.StatusUnauthorized},
		{"wrong token", "Bearer wrong", http.StatusUnauthorized},
		{"shorter prefix", "Bearer " + token[:5], http.StatusUnauthorized},
		{"correct", "Bearer " + token, http.StatusOK},
		{"trailing whitespace tolerated", "Bearer " + token + "  ", http.StatusOK},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/pods", nil)
			if tt.authHeader != "" {
				r.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body=%s)", rr.Code, tt.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestGenerateToken_UniqueAndLength(t *testing.T) {
	a, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two consecutive tokens should differ")
	}
	if len(a) < 32 {
		t.Errorf("token surprisingly short: %d chars", len(a))
	}
}
