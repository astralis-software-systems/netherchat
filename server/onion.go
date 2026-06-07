package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"time"

	"github.com/cretz/bine/tor"
)

// TorOptions controls the optional v3 onion-service listener (§1.5). It is set
// from the --tor / --tor-data-dir flags; the relay still always listens on its
// normal TCP port — the onion is an ADDITIONAL listener.
type TorOptions struct {
	Enabled bool
	DataDir string // tor state dir; empty = a fresh temp dir per run (ephemeral address)
}

// TorInstalled reports whether a `tor` binary is reachable in PATH. The server
// does NOT bundle tor; --tor is a hard error without it (the caller exits with
// install instructions), keeping the static binary free of a tor dependency.
func TorInstalled() bool {
	_, err := exec.LookPath("tor")
	return err == nil
}

// onionService is a running v3 onion service: its .onion:80 address, the local
// listener tor forwards to, and a closer for both the service and the tor process.
type onionService struct {
	addr     string
	listener net.Listener
	close    func() error
}

// Addr returns the published address, e.g. "abc123…onion:80".
func (o *onionService) Addr() string { return o.addr }

// startOnion launches an embedded tor and publishes a v3 onion service that maps
// virtual port 80 to a local listener (§1.5). The .onion address IS the service's
// public key, so reaching it authenticates the relay for free — no TLS, no CA.
// Requires `tor` in PATH (checked by the caller). Bootstrapping the service can
// take a minute; the context bounds it.
func startOnion(ctx context.Context, dataDir string, log *slog.Logger) (*onionService, error) {
	t, err := tor.Start(ctx, &tor.StartConf{DataDir: dataDir})
	if err != nil {
		return nil, fmt.Errorf("start tor (is `tor` in PATH and runnable?): %w", err)
	}

	// Publishing the descriptor can take a little while; bound it so a wedged tor
	// cannot hang startup forever.
	listenCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	svc, err := t.Listen(listenCtx, &tor.ListenConf{Version3: true, RemotePorts: []int{80}})
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("publish onion service: %w", err)
	}

	log.Info("tor onion service ready", "addr", svc.ID+".onion:80")
	return &onionService{
		addr:     svc.ID + ".onion:80",
		listener: svc,
		close: func() error {
			_ = svc.Close()
			return t.Close()
		},
	}, nil
}
