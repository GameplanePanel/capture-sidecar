// Command capture-sidecar is an optional ephemeral container that runs
// alongside a game server to capture network traffic to PCAPNG files.
// It listens on :9091 for mTLS-authenticated control commands from the
// API server: start a packet capture with a BPF filter, stop an active
// capture, poll capture status, or download a completed PCAPNG file.
//
// Captured packets are written to emptyDir volume at /tmp/captures.
// The sidecar is injected only when spec.capture.enabled = true on the
// GameServer; the capture emptyDir volume is pre-provisioned on all game
// pods (see contracts/capture-sidecar.md for full details).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/GameplanePanel/gameplane/capture-sidecar/internal/auth"
	"github.com/GameplanePanel/gameplane/capture-sidecar/internal/httpserver"
	"github.com/GameplanePanel/gameplane/capture-sidecar/internal/nodecapture"
)

// Version is overridden at build time via -ldflags (see Dockerfile).
var Version = "dev"

// shutdownTimeout bounds the graceful drain on SIGTERM. An in-flight capture
// download may legitimately still be streaming when the pod is torn down.
const shutdownTimeout = 30 * time.Second

// listenAddr and captureDataDir match the port and the captures volume
// mount in the operator's Pod specs.
const (
	listenAddr     = "0.0.0.0:9091"
	captureDataDir = "/tmp/captures"
)

// defaultVolumeBudgetBytes is the fallback used when CAPTURE_VOLUME_BUDGET_BYTES
// is unset or unparsable (e.g. run standalone outside the operator). It
// matches captureVolumeBudgetBytes in
// operator/internal/controller/gameserver_controller.go: the 1Gi "captures"
// emptyDir SizeLimit minus the same 10% safety margin.
const defaultVolumeBudgetBytes int64 = 1*1024*1024*1024 - (1*1024*1024*1024)/10

// envOrDefault returns the named environment variable's value, or fallback
// if it is unset or empty, so an operator-set env var takes effect (F-188)
// and running with no env vars at all (standalone, tests) keeps the
// hardcoded fallback.
func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	// TLS_CERT_FILE/TLS_KEY_FILE/TLS_CA_FILE are the env vars specs.md
	// documents as required, and the ones buildCaptureEphemeralContainer
	// (operator/internal/controller/gameserver_controller.go) actually sets
	// on the ephemeral container (F-188). The listen address and capture
	// directory are fixed: the operator's Pod specs mount /tmp/captures and
	// expose port 9091.
	certFile := envOrDefault("TLS_CERT_FILE", "/etc/tls/tls.crt")
	keyFile := envOrDefault("TLS_KEY_FILE", "/etc/tls/tls.key")
	caFile := envOrDefault("TLS_CA_FILE", "/etc/tls/ca.crt")
	nodeWorker := flag.Bool("node-worker", false, "Run one operator-bound node diagnostic capture and exit")
	artifactOnly := flag.Bool("artifacts-only", false, "Serve completed node capture artifacts without capture controls")

	// The operator sets CAPTURE_VOLUME_BUDGET_BYTES on the capture ephemeral
	// container (see buildCaptureEphemeralContainer in
	// operator/internal/controller/gameserver_controller.go), derived from
	// the "captures" emptyDir's own SizeLimit so the two can't drift apart
	// (F-187). Unset or invalid falls back to defaultVolumeBudgetBytes.
	volumeBudgetBytes := defaultVolumeBudgetBytes
	if v := os.Getenv("CAPTURE_VOLUME_BUDGET_BYTES"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil || parsed <= 0 {
			slog.Error("invalid CAPTURE_VOLUME_BUDGET_BYTES, using default", "value", v, "default", defaultVolumeBudgetBytes)
		} else {
			volumeBudgetBytes = parsed
		}
	}
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *nodeWorker {
		var cfg nodecapture.Config
		if *artifactOnly || json.Unmarshal([]byte(os.Getenv("NODE_CAPTURE_CONFIG")), &cfg) != nil {
			slog.Error("invalid node capture configuration")
			os.Exit(1)
		}
		if err := nodecapture.Run(ctx, cfg, captureDataDir); err != nil {
			slog.Error("node capture failed", "err", err)
			os.Exit(1)
		}
		return
	}

	// Create capture server. ctx (cancelled on SIGTERM/SIGINT) is the parent
	// for every capture goroutine, so shutdown cancels in-flight captures
	// instead of leaking them past server exit.
	captureServer := httpserver.NewServer(ctx, captureDataDir, volumeBudgetBytes, os.Getenv("GAMEPLANE_SERVER_UID"))

	// Set up mTLS. The certificates come from the same per-GameServer
	// `agent-tls` Secret the agent uses, mounted at /etc/tls.
	tlsConfig, err := auth.ServerTLS(certFile, keyFile, caFile)
	if err != nil {
		slog.Error("failed to setup TLS", "err", err)
		os.Exit(1)
	}

	// Every capture endpoint is wrapped in the mTLS middleware; /healthz is
	// the only route not additionally wrapped by it. That does not make it
	// reachable without a client certificate: the http.Server below serves
	// every route, /healthz included, over the same TLS listener whose
	// TLSConfig requires and verifies a client certificate at the handshake
	// (see HandleHealthz's doc comment for why nothing actually calls this
	// route today; F-193).
	mux := captureServer.Routes(auth.Middleware)
	if *artifactOnly {
		mux = captureServer.ArtifactRoutes(auth.Middleware)
	}

	server := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
		// ReadHeaderTimeout guards against slow-header connections holding the
		// server open indefinitely (gosec G112).
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout bounds how long reading a full request (headers + body)
		// may take. Every request body handled here is a small JSON control
		// message, so this is safe to bound tightly.
		ReadTimeout: 30 * time.Second,
		// WriteTimeout is deliberately left unset (zero == no limit): capture
		// file downloads can be multi-GiB and legitimately take far longer to
		// stream than any fixed response deadline would allow.
	}

	slog.Info("capture-sidecar starting", "addr", server.Addr, "version", Version)

	// Serve TLS with client-certificate verification (RequireAndVerifyClientCert
	// and TLS 1.2 minimum, from auth.ServerTLS). This is the sidecar's only
	// authentication boundary: on a plaintext listener anything that can reach
	// the pod network could start captures and download another server's
	// packet data, so a plain-HTTP server must not be used here. Empty file
	// arguments make ListenAndServeTLS use the certificates already in
	// server.TLSConfig, matching Gameplane's agent/cmd/main.go.
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}

	// Finalize any in-flight capture so its PCAPNG file is closed and valid
	// rather than truncated and unreadable. This is called after HTTP shutdown,
	// so no new requests will start new captures or stop the one we're finalizing.
	captureServer.FinalizeCurrentCapture()

	slog.Info("capture-sidecar stopped")
}
