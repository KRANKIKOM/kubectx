package proxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GenerateToken returns a base64url-encoded 256-bit random token suitable
// for use as a kubeconfig bearer token.
func GenerateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// withTokenAuth wraps next so that requests must carry
// `Authorization: Bearer <token>`. A missing or mismatched token returns
// 401 with a metav1.Status body, so kubectl renders a clean error.
//
// The comparison uses subtle.ConstantTimeCompare to avoid leaking the
// token via response timing.
func withTokenAuth(token string, next http.Handler) http.Handler {
	expected := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeUnauthorized(w, "missing bearer token")
			return
		}
		got := []byte(strings.TrimSpace(auth[len(prefix):]))
		if len(got) != len(expected) || subtle.ConstantTimeCompare(got, expected) != 1 {
			writeUnauthorized(w, "invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	status := &metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Message:  "[kubectx] " + msg,
		Reason:   metav1.StatusReasonUnauthorized,
		Code:     http.StatusUnauthorized,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(status)
}
