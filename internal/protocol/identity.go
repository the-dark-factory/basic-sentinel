// Package protocol defines the signed message types exchanged between
// Supervisor and Fixer, and the Ed25519 identity system they use.
//
// Adapted from forge/internal/crypto/chain.go — same pattern, zero internal deps.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// Identity holds an Ed25519 key pair for a sentinel role.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Role       string // "supervisor" or "fixer"
}

// LoadOrCreateIdentity loads an Ed25519 key from disk, or generates one.
func LoadOrCreateIdentity(keyPath, role string) (*Identity, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		// Generate and save
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		if err := os.WriteFile(keyPath, priv, 0600); err != nil {
			return nil, fmt.Errorf("save key: %w", err)
		}
		os.WriteFile(keyPath+".pub", []byte(hex.EncodeToString(pub)), 0644)
		return &Identity{PrivateKey: priv, PublicKey: pub, Role: role}, nil
	}

	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key file: expected %d bytes, got %d", ed25519.PrivateKeySize, len(data))
	}
	priv := ed25519.PrivateKey(data)
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{PrivateKey: priv, PublicKey: pub, Role: role}, nil
}

// PubKeyHex returns the hex-encoded public key.
func (id *Identity) PubKeyHex() string {
	return hex.EncodeToString(id.PublicKey)
}

// Sign signs arbitrary data and returns the hex-encoded signature.
func (id *Identity) Sign(data []byte) string {
	sig := ed25519.Sign(id.PrivateKey, data)
	return hex.EncodeToString(sig)
}

// VerifySignature checks a hex-encoded signature against a hex-encoded public key.
func VerifySignature(pubKeyHex, signatureHex string, data []byte) (bool, error) {
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("decode pubkey: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid pubkey size: %d", len(pubBytes))
	}
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes), nil
}
