// fixerd is the Sentinel Fixer — acts only on signed instructions from the Supervisor.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sentinel/internal/config"
	"sentinel/internal/protocol"
	"sentinel/internal/remedy"
)

func main() {
	configPath := flag.String("config", "sentinel.json", "path to sentinel config")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	cfg.Defaults()

	if cfg.Fixer.SupervisorPubKey == "" {
		log.Fatal("fixer: supervisor_pubkey must be set in config")
	}

	identity, err := protocol.LoadOrCreateIdentity(cfg.Fixer.KeyPath, "fixer")
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}
	log.Printf("fixer: identity loaded, pubkey=%s", identity.PubKeyHex()[:16]+"...")
	log.Printf("fixer: trusting supervisor pubkey=%s", cfg.Fixer.SupervisorPubKey[:16]+"...")

	fixer := remedy.New(identity, cfg.Fixer)
	fixer.SetAlertDispatcher(&remedy.AlertDispatcher{
		LogPath:    cfg.Alert.LogPath,
		WebhookURL: cfg.Alert.WebhookURL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("fixer: received %s, shutting down", sig)
		cancel()
	}()

	if err := fixer.Run(ctx); err != nil {
		log.Fatalf("fixer: %v", err)
	}
}
