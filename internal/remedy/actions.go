package remedy

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// Action implementations. Each returns a detail string on success or an error.

// RestartService restarts a systemd service (local only).
func RestartService(service string) (string, error) {
	cmd := exec.Command("systemctl", "restart", service)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl restart %s: %s: %w", service, string(output), err)
	}
	return fmt.Sprintf("systemctl restart %s succeeded", service), nil
}

// RestartServiceSSH restarts a systemd service on a remote host via SSH.
func RestartServiceSSH(host, service, keyPath string) (string, error) {
	args := []string{
		"-i", keyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=10",
		host,
		"sudo", "systemctl", "restart", service,
	}
	cmd := exec.Command("ssh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ssh %s systemctl restart %s: %s: %w", host, service, string(output), err)
	}
	return fmt.Sprintf("remote restart %s on %s succeeded", service, host), nil
}

// RequeueParams are the parameters for requeue actions.
type RequeueParams struct {
	JobID string `json:"job_id"`
}

// RequeueStageParams are the parameters for stage requeue actions.
type RequeueStageParams struct {
	StageID string `json:"stage_id"`
	JobID   string `json:"job_id"`
}

// RestartParams are the parameters for restart actions.
type RestartParams struct {
	Service string `json:"service"`
	Host    string `json:"host"`     // empty = local
	KeyPath string `json:"key_path"` // SSH key for remote
}

// ParseRequeueParams parses the JSON parameters for a requeue action.
func ParseRequeueParams(raw string) (*RequeueParams, error) {
	var p RequeueParams
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("parse requeue params: %w", err)
	}
	if p.JobID == "" {
		return nil, fmt.Errorf("missing job_id in requeue params")
	}
	return &p, nil
}

// ParseRestartParams parses the JSON parameters for a restart action.
func ParseRestartParams(raw string) (*RestartParams, error) {
	var p RestartParams
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("parse restart params: %w", err)
	}
	if p.Service == "" {
		return nil, fmt.Errorf("missing service in restart params")
	}
	return &p, nil
}
