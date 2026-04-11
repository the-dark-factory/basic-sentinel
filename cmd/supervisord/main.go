// supervisord is the Sentinel Supervisor — observe-only, never mutates state.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sentinel/internal/config"
	"sentinel/internal/observe"
	"sentinel/internal/protocol"
)

func main() {
	configPath := flag.String("config", "sentinel.json", "path to sentinel config")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.Defaults()

	identity, err := protocol.LoadOrCreateIdentity(cfg.Supervisor.KeyPath, "supervisor")
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}
	log.Printf("supervisor: identity loaded, pubkey=%s", identity.PubKeyHex()[:16]+"...")

	observer := observe.New(identity, cfg.Supervisor, cfg.Alert, cfg.Fixer.SocketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGTERM/SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("supervisor: received %s, shutting down", sig)
		cancel()
	}()

	observer.Run(ctx)
}
