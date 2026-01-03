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

// HealthServer provides HTTP health check endpoints
type HealthServer struct {
	port   int
	server *http.Server
	status *HealthStatus
	mu     sync.RWMutex
}

// HealthStatus represents the current health status
type HealthStatus struct {
	Healthy       bool      `json:"healthy"`
	NATSConnected bool      `json:"nats_connected"`
	EnclaveConnected bool   `json:"enclave_connected"`
	LastCheck     time.Time `json:"last_check"`
	Uptime        string    `json:"uptime"`
	Version       string    `json:"version"`
}

var startTime = time.Now()

// NewHealthServer creates a new health server
func NewHealthServer(port int) *HealthServer {
	return &HealthServer{
		port: port,
		status: &HealthStatus{
			Healthy: true,
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

	h.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", h.port),
		Handler: mux,
	}

	log.Info().Int("port", h.port).Msg("Starting health server")

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

// UpdateStatus updates the health status
func (h *HealthServer) UpdateStatus(natsConnected, enclaveConnected bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.status.NATSConnected = natsConnected
	h.status.EnclaveConnected = enclaveConnected
	h.status.Healthy = natsConnected && enclaveConnected
	h.status.LastCheck = time.Now()
	h.status.Uptime = time.Since(startTime).String()
}

// handleHealth handles the /health endpoint
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

// handleReady handles the /ready endpoint (for Kubernetes readiness probes)
func (h *HealthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	healthy := h.status.Healthy
	h.mu.RUnlock()

	if healthy {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready"))
	}
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
