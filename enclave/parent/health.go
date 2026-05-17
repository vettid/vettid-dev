package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// HealthServer provides HTTP health check endpoints. The same server
// also serves the /internal/reclaim-from-pcr0 admin endpoint used by
// deploy.sh during Phase 4.5 to drain users from OLD to NEW without
// waiting for OLD's M1 handoff (which OLD can't emit if its vault-
// manager has a verification bug). The endpoint binds to localhost
// only — SSM RunShellScript is the auth boundary.
type HealthServer struct {
	port     int
	bindAddr string
	server   *http.Server
	status   *HealthStatus
	mu       sync.RWMutex
	routing  *RoutingManager // wired post-construction via SetRouting
}

// SetRouting wires the routing manager so the /internal/reclaim-from-pcr0
// admin endpoint can act on it. Called after Start() — the http handler
// guards against nil so the endpoint just 503s before routing is up.
func (h *HealthServer) SetRouting(r *RoutingManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.routing = r
}

// HealthStatus represents the current health status
//
// `Healthy` is the liveness signal: true from process start until
// shutdown, regardless of whether NATS / vsock are connected. It
// flips to false only when the process is in a known-bad state
// (currently unused — process exit is the only such signal today).
//
// `Ready` is the readiness signal: true only when both NATS and the
// enclave are connected. The deploy script probes /ready after a
// new instance comes InService; /health is for systemd / liveness
// probes that just need to know the process is alive.
//
// Earlier versions conflated the two — Healthy = natsConnected &&
// enclaveConnected — so the endpoint returned 503 for the entire
// vsock handshake window (1-3 min on cold boot). The deploy script's
// 5-min budget intermittently won that race, producing loud
// false-failure ERROR lines on every deploy.
type HealthStatus struct {
	Healthy          bool      `json:"healthy"`
	Ready            bool      `json:"ready"`
	NATSConnected    bool      `json:"nats_connected"`
	EnclaveConnected bool      `json:"enclave_connected"`
	LastCheck        time.Time `json:"last_check"`
	Uptime           string    `json:"uptime"`
	Version          string    `json:"version"`
}

var startTime = time.Now()

// NewHealthServer creates a new health server. bindAddr blank
// preserves the prior production default of 127.0.0.1; the Tier-2
// harness passes 0.0.0.0 so its container's port mapping can reach
// the endpoint.
func NewHealthServer(port int, bindAddr string) *HealthServer {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	return &HealthServer{
		port:     port,
		bindAddr: bindAddr,
		status: &HealthStatus{
			Healthy: true, // liveness — true from start
			Ready:   false, // readiness — flips true once both connections land
			Version: Version,
		},
	}
}

// Start starts the health server
func (h *HealthServer) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/ready", h.handleReady)
	mux.HandleFunc("/metrics", h.handleMetrics)
	mux.HandleFunc("/internal/reclaim-from-pcr0", h.handleReclaimFromPCR0)

	h.server = &http.Server{
		// Localhost-only by default — the reclaim endpoint is
		// unauthenticated and must not be reachable from outside this
		// host. SSM RunShellScript bridges deploy.sh through to here.
		// The Tier-2 harness overrides to 0.0.0.0 so its driver
		// running on the compose host can reach /ready via the
		// container's port mapping.
		Addr:    fmt.Sprintf("%s:%d", h.bindAddr, h.port),
		Handler: mux,
	}

	log.Info().Str("addr", h.server.Addr).Msg("Starting health server")

	if err := h.server.ListenAndServe(); err != http.ErrServerClosed {
		log.Error().Err(err).Msg("Health server error")
	}
}

// Stop stops the health server
func (h *HealthServer) Stop() {
	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.server.Shutdown(ctx)
	}
}

// UpdateStatus updates the readiness status from the connection
// state callback chain. Liveness (Healthy) stays true throughout —
// only the readiness signal tracks whether the parent has finished
// its boot handshake. See HealthStatus doc comment for the split.
func (h *HealthServer) UpdateStatus(natsConnected, enclaveConnected bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.status.NATSConnected = natsConnected
	h.status.EnclaveConnected = enclaveConnected
	h.status.Ready = natsConnected && enclaveConnected
	h.status.LastCheck = time.Now()
	h.status.Uptime = time.Since(startTime).String()
}

// handleHealth handles the /health endpoint — liveness only. Returns
// 200 if the process is alive (which it is, by virtue of serving the
// request). Used by systemd-style liveness probes that want to know
// "is the process running" not "has it finished booting". The
// deploy.sh enclave-health gate should probe /ready instead.
func (h *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	status := *h.status
	h.mu.RUnlock()

	status.Uptime = time.Since(startTime).String()
	w.Header().Set("Content-Type", "application/json")
	if !status.Healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(status)
}

// handleReady handles the /ready endpoint — readiness signal.
// Returns 200 only when both NATS and the enclave are connected.
// Used by deploy.sh's post-launch verification (the parent's boot
// sequence takes 1-3 min cold; until then this returns 503).
func (h *HealthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	status := *h.status
	h.mu.RUnlock()

	status.Uptime = time.Since(startTime).String()
	w.Header().Set("Content-Type", "application/json")
	if !status.Ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(status)
}

// handleReclaimFromPCR0 is the admin endpoint that deploy.sh Phase 4.5
// calls to drain users from OLD to NEW during the migration window.
// Query param `pcr0` is the OLD PCR0 (hex). Returns the number of
// users reclaimed and the running PCR0 for sanity-check.
//
// Bound to 127.0.0.1 only — auth boundary is "you must be on this
// host to call it" which during deploys = "SSM RunShellScript".
//
// Background: the M1 routing handoff fires from OLD's
// dispatchMigrateConsent when a user accepts the migration prompt.
// OLD-with-broken-vault-manager (yesterday's case) couldn't verify
// the config and short-circuited before reaching the handoff branch,
// so users stayed pinned to OLD forever and required manual ASG
// termination to flip them to NEW. This endpoint lets the deploy
// script proactively trigger the move once Phase 4.5 has confirmed
// NEW is healthy.
func (h *HealthServer) handleReclaimFromPCR0(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	routing := h.routing
	h.mu.RUnlock()
	if routing == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"routing not yet initialized"}`))
		return
	}
	oldPCR0 := r.URL.Query().Get("pcr0")
	if oldPCR0 == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"missing pcr0 query parameter"}`))
		return
	}
	claimed, err := routing.ReclaimUsersFromPCR0(oldPCR0)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Error().Err(err).Str("old_pcr0", oldPCR0).Msg("reclaim-from-pcr0 failed")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         err.Error(),
			"claimed":       claimed,
			"running_pcr0":  routing.pcr0,
			"requested_old": oldPCR0,
		})
		return
	}
	log.Info().
		Int("claimed", claimed).
		Str("old_pcr0", oldPCR0).
		Str("new_pcr0", routing.pcr0).
		Msg("Admin reclaim-from-pcr0 completed")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"claimed":       claimed,
		"running_pcr0":  routing.pcr0,
		"requested_old": oldPCR0,
	})
}

// handleMetrics handles the /metrics endpoint (Prometheus format)
func (h *HealthServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	status := *h.status
	h.mu.RUnlock()

	healthyVal := 0
	if status.Healthy {
		healthyVal = 1
	}
	natsVal := 0
	if status.NATSConnected {
		natsVal = 1
	}
	enclaveVal := 0
	if status.EnclaveConnected {
		enclaveVal = 1
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "# HELP vettid_parent_healthy Whether the parent process is healthy\n")
	fmt.Fprintf(w, "# TYPE vettid_parent_healthy gauge\n")
	fmt.Fprintf(w, "vettid_parent_healthy %d\n", healthyVal)
	fmt.Fprintf(w, "# HELP vettid_parent_nats_connected Whether connected to NATS\n")
	fmt.Fprintf(w, "# TYPE vettid_parent_nats_connected gauge\n")
	fmt.Fprintf(w, "vettid_parent_nats_connected %d\n", natsVal)
	fmt.Fprintf(w, "# HELP vettid_parent_enclave_connected Whether connected to enclave\n")
	fmt.Fprintf(w, "# TYPE vettid_parent_enclave_connected gauge\n")
	fmt.Fprintf(w, "vettid_parent_enclave_connected %d\n", enclaveVal)
	fmt.Fprintf(w, "# HELP vettid_parent_uptime_seconds Uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE vettid_parent_uptime_seconds counter\n")
	fmt.Fprintf(w, "vettid_parent_uptime_seconds %.0f\n", time.Since(startTime).Seconds())
}
