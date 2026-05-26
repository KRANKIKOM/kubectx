package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ahmetb/kubectx/internal/env"
)

// nonMutatingPostPatterns match Kubernetes "review" endpoints that use POST
// but don't create persistent resources. Patterns are anchored to known API
// groups to prevent spoofing via custom resource names.
var nonMutatingPostPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^/apis/authorization\.k8s\.io/[^/]+/selfsubjectaccessreviews$`),
	regexp.MustCompile(`^/apis/authorization\.k8s\.io/[^/]+/subjectaccessreviews$`),
	regexp.MustCompile(`^/apis/authorization\.k8s\.io/[^/]+/namespaces/[^/]+/localsubjectaccessreviews$`),
	regexp.MustCompile(`^/apis/authorization\.k8s\.io/[^/]+/selfsubjectrulesreviews$`),
	regexp.MustCompile(`^/apis/authentication\.k8s\.io/[^/]+/tokenreviews$`),
	regexp.MustCompile(`^/apis/authentication\.k8s\.io/[^/]+/selfsubjectreviews$`),
}

var debugLog = func() *log.Logger {
	if _, ok := os.LookupEnv(env.EnvDebug); ok {
		return log.New(os.Stderr, "[readonly-proxy] ", log.Ltime)
	}
	return log.New(nopWriter{}, "", 0)
}()

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// ReadonlyProxy is a reverse proxy that only allows read-only HTTP methods.
type ReadonlyProxy struct {
	server   *http.Server
	listener net.Listener
}

// Config holds information needed to start the readonly proxy.
type Config struct {
	KubeconfigPath string
	ContextName    string
	// Policy describes which requests to allow. The zero value is
	// equivalent to PresetStrict.
	Policy Policy
	// ListenAddr controls where the listener binds, e.g. "0.0.0.0:8443".
	// Empty defaults to "127.0.0.1:0" (loopback, ephemeral port).
	ListenAddr string
	// TLS, when set, makes the proxy serve HTTPS using the provided
	// certificate. Required for cross-sandbox use; loopback can stay HTTP.
	TLS *ServerTLS
	// AuthToken, when set, requires `Authorization: Bearer <token>` on
	// every request. Required whenever the listener is reachable from
	// anything other than loopback.
	AuthToken string
}

// Start creates and starts a readonly reverse proxy on a random localhost port.
// The proxy loads TLS/auth config from the kubeconfig and forwards requests
// to the real API server according to cfg.Policy (or the strict default).
func Start(cfg Config) (*ReadonlyProxy, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: cfg.KubeconfigPath}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: cfg.ContextName}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	restCfg, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	targetURL, err := url.Parse(restCfg.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL %q: %w", restCfg.Host, err)
	}

	transport, err := rest.TransportFor(restCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}

	var handler http.Handler = NewHandlerWithPolicy(targetURL, transport, cfg.Policy)
	if cfg.AuthToken != "" {
		handler = withTokenAuth(cfg.AuthToken, handler)
	}

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	// Surface server errors loudly. A dead proxy means kubectl gets
	// ECONNREFUSED with no context — the user's prompt still shows the
	// "readonly shell" badge while no enforcement is happening.
	stderrLog := log.New(os.Stderr, "[kubectx readonly-proxy] ", log.Ltime)
	srv := &http.Server{Handler: handler, ErrorLog: stderrLog}
	if cfg.TLS != nil {
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cfg.TLS.Cert}}
	}
	go func() {
		var serveErr error
		if cfg.TLS != nil {
			serveErr = srv.ServeTLS(listener, "", "")
		} else {
			serveErr = srv.Serve(listener)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			stderrLog.Printf("server died: %v", serveErr)
		}
	}()

	debugLog.Printf("started on %s, proxying to %s", listener.Addr(), targetURL)

	return &ReadonlyProxy{
		server:   srv,
		listener: listener,
	}, nil
}

// Addr returns the listener address (e.g. "127.0.0.1:54321").
func (p *ReadonlyProxy) Addr() string {
	return p.listener.Addr().String()
}

// Shutdown gracefully stops the proxy.
func (p *ReadonlyProxy) Shutdown(ctx context.Context) error {
	debugLog.Printf("shutting down")
	return p.server.Shutdown(ctx)
}

// NewHandler creates the readonly proxy HTTP handler with the strict default policy.
// Exported for testing with a fake backend.
func NewHandler(target *url.URL, transport http.RoundTripper) http.Handler {
	return NewHandlerWithPolicy(target, transport, PresetStrict())
}

// checkRequest preserves the historical strict-default decision function for
// tests that exercise it directly. New code should use Policy.Decide.
func checkRequest(r *http.Request) (reason string, allowed bool) {
	return PresetStrict().Decide(r)
}

// NewHandlerWithPolicy creates the readonly proxy HTTP handler using the given policy.
func NewHandlerWithPolicy(target *url.URL, transport http.RoundTripper, policy Policy) http.Handler {
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = transport
	rp.FlushInterval = -1 // flush immediately for streaming (logs -f, watches)
	rp.ErrorLog = debugLog

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		debugLog.Printf(">> %s %s", r.Method, r.URL.Path)

		if reason, ok := policy.Decide(r); !ok {
			debugLog.Printf("<< %s %s -> 405 (%s)", r.Method, r.URL.Path, reason)
			writeBlockedResponse(w, r.Method,
				fmt.Sprintf("[kubectx] readonly mode: %s", reason))
			return
		}

		debugLog.Printf("<< %s %s -> proxied", r.Method, r.URL.Path)
		rp.ServeHTTP(w, r)
	})
}

// isUpgrade returns true if the request is a protocol upgrade (SPDY/WebSocket).
// Tokenizes the Connection header so values like "keep-alive, Upgrade" are
// recognized.
func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return true
	}
	for _, tok := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "Upgrade") {
			return true
		}
	}
	return false
}

// isReadOnly returns true for safe HTTP methods that never modify state.
func isReadOnly(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// isNonMutatingPost returns true for Kubernetes "review" endpoints that use
// POST but don't create persistent resources (e.g. SubjectAccessReview).
// Patterns are anchored to known API groups to prevent spoofing.
func isNonMutatingPost(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	for _, re := range nonMutatingPostPatterns {
		if re.MatchString(r.URL.Path) {
			return true
		}
	}
	return false
}

// isDryRun returns true if the request has ?dryRun=All, which means
// the API server will validate but not persist the request.
func isDryRun(r *http.Request) bool {
	return r.URL.Query().Get("dryRun") == "All"
}

func writeBlockedResponse(w http.ResponseWriter, method, message string) {
	status := &metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Message:  message,
		Reason:   metav1.StatusReasonMethodNotAllowed,
		Code:     http.StatusMethodNotAllowed,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusMethodNotAllowed)
	json.NewEncoder(w).Encode(status)
}
