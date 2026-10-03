package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type API struct {
	store   *Store
	logger  *slog.Logger
	limiter *rateLimiter
}

type principal struct {
	AccountID string
	DeviceID  string
	FamilyID  string
}

type principalKey struct{}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHandler(store *Store, logger *slog.Logger) http.Handler {
	api := &API{store: store, logger: logger, limiter: newRateLimiter()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", api.health)
	mux.HandleFunc("GET /readyz", api.ready)
	mux.HandleFunc("GET /v1/status", api.status)
	mux.Handle("POST /v1/accounts", api.sensitive(http.HandlerFunc(api.createAccount)))
	mux.Handle("POST /v1/devices/enroll", api.sensitive(http.HandlerFunc(api.enrollDevice)))
	mux.Handle("POST /v1/auth/challenges", api.sensitive(http.HandlerFunc(api.createChallenge)))
	mux.Handle("POST /v1/auth/tokens", api.sensitive(http.HandlerFunc(api.exchangeChallenge)))
	mux.Handle("POST /v1/auth/refresh", api.sensitive(http.HandlerFunc(api.refreshTokens)))
	mux.Handle("GET /v1/devices", api.requireAuth(http.HandlerFunc(api.listDevices)))
	mux.Handle("DELETE /v1/devices/{deviceID}", api.requireAuth(http.HandlerFunc(api.revokeDevice)))
	mux.Handle("GET /v1/vault", api.requireAuth(http.HandlerFunc(api.getVault)))
	mux.Handle("PUT /v1/vault", api.requireAuth(http.HandlerFunc(api.putVault)))
	mux.Handle("PUT /v1/recovery", api.requireAuth(http.HandlerFunc(api.rotateRecovery)))
	return api.logging(api.globalLimit(securityHeaders(mux)))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(response, request)
	})
}

func (a *API) health(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusNoContent)
}

func (a *API) ready(response http.ResponseWriter, request *http.Request) {
	if err := a.store.db.PingContext(request.Context()); err != nil {
		a.writeError(response, http.StatusServiceUnavailable, "database_unavailable", "database is unavailable")
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (a *API) status(response http.ResponseWriter, _ *http.Request) {
	a.writeJSON(response, http.StatusOK, map[string]any{
		"protocolVersion": ProtocolVersion,
		"instanceId":      a.store.InstanceID(),
		"maxVaultBytes":   MaxVaultBytes,
		"registration":    "invite",
	})
}

func (a *API) decodeJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(response, request.Body, MaxJSONBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		a.writeError(response, http.StatusBadRequest, "invalid_json", "request body is invalid")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		a.writeError(response, http.StatusBadRequest, "invalid_json", "request must contain one JSON value")
		return false
	}
	return true
}

func (a *API) writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		a.logger.Error("encode response", "error", err)
	}
}

func (a *API) writeError(response http.ResponseWriter, status int, code, message string) {
	a.writeJSON(response, status, apiError{Code: code, Message: message})
}

func (a *API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		header := request.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
			a.writeError(response, http.StatusUnauthorized, "authentication_required", "valid access token required")
			return
		}
		identity, err := a.authenticate(request.Context(), header[7:])
		if err != nil {
			a.writeError(response, http.StatusUnauthorized, "invalid_access_token", "access token is invalid or expired")
			return
		}
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), principalKey{}, identity)))
	})
}

func requestPrincipal(request *http.Request) principal {
	return request.Context().Value(principalKey{}).(principal)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(value []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(value)
}

func (a *API) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: response}
		next.ServeHTTP(recorder, request)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		a.logger.Info("request", "method", request.Method, "path", request.URL.Path, "status", status, "duration_ms", time.Since(started).Milliseconds())
	})
}

type rateWindow struct {
	started time.Time
	count   int
}

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}

func newRateLimiter() *rateLimiter { return &rateLimiter{windows: make(map[string]rateWindow)} }

func (r *rateLimiter) allow(key string, limit int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	window := r.windows[key]
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = rateWindow{started: now}
	}
	window.count++
	r.windows[key] = window
	if len(r.windows) > 10_000 {
		for candidate, value := range r.windows {
			if now.Sub(value.started) >= 2*time.Minute {
				delete(r.windows, candidate)
			}
		}
	}
	return window.count <= limit
}

func remoteHost(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func (a *API) globalLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !a.limiter.allow("global:"+remoteHost(request), 300) {
			response.Header().Set("Retry-After", "60")
			a.writeError(response, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		next.ServeHTTP(response, request)
	})
}

func (a *API) sensitive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		key := fmt.Sprintf("sensitive:%s:%s", remoteHost(request), request.URL.Path)
		if !a.limiter.allow(key, 20) {
			response.Header().Set("Retry-After", "60")
			a.writeError(response, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		next.ServeHTTP(response, request)
	})
}
