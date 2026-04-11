#!/usr/bin/env bash
# Deploy Sentinel to Gertrude (192.168.0.252)
# Usage: ./deploy/deploy-gertrude.sh [config.json]
set -euo pipefail

TARGET="tony@192.168.0.252"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
CONFIG="${1:-sentinel-gertrude.json}"

echo "=== Building for linux/arm64 ==="
GOOS=linux GOARCH=amd64 go build -o bin/supervisord-linux ./cmd/supervisord/
GOOS=linux GOARCH=amd64 go build -o bin/fixerd-linux ./cmd/fixerd/
echo "Built: bin/supervisord-linux bin/fixerd-linux"

echo ""
echo "=== Deploying to Gertrude ($TARGET) ==="

# Create directories
ssh -i "$SSH_KEY" "$TARGET" "sudo mkdir -p /opt/sentinel/{bin,keys,logs} /var/run/sentinel"

# Create sentinel user if needed
ssh -i "$SSH_KEY" "$TARGET" "id sentinel 2>/dev/null || sudo useradd -r -s /usr/sbin/nologin -d /opt/sentinel sentinel"

# Copy binaries
scp -i "$SSH_KEY" bin/supervisord-linux "$TARGET":/tmp/supervisord
scp -i "$SSH_KEY" bin/fixerd-linux "$TARGET":/tmp/fixerd
ssh -i "$SSH_KEY" "$TARGET" "sudo mv /tmp/supervisord /opt/sentinel/bin/supervisord && sudo mv /tmp/fixerd /opt/sentinel/bin/fixerd && sudo chmod +x /opt/sentinel/bin/*"

# Copy config
scp -i "$SSH_KEY" "$CONFIG" "$TARGET":/tmp/sentinel-config.json
ssh -i "$SSH_KEY" "$TARGET" "sudo mv /tmp/sentinel-config.json /opt/sentinel/config.json"

# Copy systemd units
scp -i "$SSH_KEY" deploy/supervisord.service "$TARGET":/tmp/supervisord.service
scp -i "$SSH_KEY" deploy/fixerd.service "$TARGET":/tmp/fixerd.service
ssh -i "$SSH_KEY" "$TARGET" "sudo mv /tmp/supervisord.service /etc/systemd/system/ && sudo mv /tmp/fixerd.service /etc/systemd/system/"

# Set permissions
ssh -i "$SSH_KEY" "$TARGET" "sudo chown -R sentinel:sentinel /opt/sentinel /var/run/sentinel"

# Reload and restart
ssh -i "$SSH_KEY" "$TARGET" "sudo systemctl daemon-reload && sudo systemctl enable supervisord fixerd && sudo systemctl restart supervisord fixerd"

echo ""
echo "=== Checking status ==="
ssh -i "$SSH_KEY" "$TARGET" "sudo systemctl status supervisord fixerd --no-pager -l" || true

echo ""
echo "=== Deployment complete ==="
echo "Supervisor pubkey:"
ssh -i "$SSH_KEY" "$TARGET" "cat /opt/sentinel/keys/supervisor.key.pub 2>/dev/null || echo '(will be generated on first run)'"
echo ""
echo "After first run, update config.json with supervisor_pubkey for the fixer."
