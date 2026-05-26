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
// On success the Authorization header is removed before the request
// reaches next. This matters for two reasons:
//   - the upstream apiserver should never see the sandbox's bearer token
//     (it would otherwise show up in audit logs)
//   - client-go's BearerAuthRoundTripper *skips* injecting the cluster
//     credential when Authorization is already set, so leaving the
//     sandbox token in place would silently break bearer-auth clusters
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
		// Only strip leading whitespace from the candidate token. Trailing
		// whitespace isn't part of any legitimate bearer token grammar and
		// permitting it would broaden the equality definition for no gain.
		got := []byte(strings.TrimLeft(auth[len(prefix):], " \t"))
		if len(got) != len(expected) || subtle.ConstantTimeCompare(got, expected) != 1 {
			writeUnauthorized(w, "invalid bearer token")
			return
		}
		// Authenticated: strip the header so the upstream apiserver never
		// sees it and client-go's transport can inject the real cluster
		// credential.
		r.Header.Del("Authorization")
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
