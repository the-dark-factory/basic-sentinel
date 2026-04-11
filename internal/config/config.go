// Package config defines the sentinel configuration structure.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SentinelConfig is the top-level configuration for both Supervisor and Fixer.
type SentinelConfig struct {
	Supervisor SupervisorConfig `json:"supervisor"`
	Fixer      FixerConfig      `json:"fixer"`
	Alert      AlertConfig      `json:"alert"`
}

type SupervisorConfig struct {
	KeyPath         string        `json:"key_path"`
	PollIntervalSec int           `json:"poll_interval_sec"`
	Checks          []CheckConfig `json:"checks"`
}

// PollInterval returns the polling interval as a time.Duration.
func (s *SupervisorConfig) PollInterval() time.Duration {
	if s.PollIntervalSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(s.PollIntervalSec) * time.Second
}

type CheckConfig struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`       // "http", "tls", "process", "forge_diagnostics"
	URL        string `json:"url"`        // for http/tls checks
	TimeoutSec int    `json:"timeout_sec"`
	// For forge_diagnostics checks
	AuthToken              string `json:"auth_token"`
	StuckJobThresholdMin   int    `json:"stuck_job_threshold_min"`
	OrphanedStageThresholdMin int `json:"orphaned_stage_threshold_min"`
	QueueDepthWarning      int    `json:"queue_depth_warning"`
	// For process checks
	ProcessName string `json:"process_name"`
	// Remediation: what action to take if this check fails
	RemediationAction string `json:"remediation_action"` // e.g. "restart_forge", "restart_ollama"
	RemediationParams string `json:"remediation_params"` // JSON params for the action
}

// Timeout returns the check timeout as a time.Duration.
func (c *CheckConfig) Timeout() time.Duration {
	if c.TimeoutSec <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.TimeoutSec) * time.Second
}

type FixerConfig struct {
	KeyPath            string      `json:"key_path"`
	SocketPath         string      `json:"socket_path"`
	SupervisorPubKey   string      `json:"supervisor_pubkey"`
	ForgeDBPath        string      `json:"forge_db_path"`
	ForgeAPIURL        string      `json:"forge_api_url"`
	ForgeAPISecret     string      `json:"forge_api_secret"`
	Safety             SafetyConfig `json:"safety"`
}

type SafetyConfig struct {
	MaxRequeuesPerJobPerHour int `json:"max_requeues_per_job_per_hour"`
	MaxRequeuesPerStageTotal int `json:"max_requeues_per_stage_total"`
	RestartCooldownSec       int `json:"restart_cooldown_sec"`
	MaxRestartsPerHour       int `json:"max_restarts_per_hour"`
}

// RestartCooldown returns the restart cooldown as a time.Duration.
func (s *SafetyConfig) RestartCooldown() time.Duration {
	if s.RestartCooldownSec <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(s.RestartCooldownSec) * time.Second
}

type AlertConfig struct {
	LogPath    string `json:"log_path"`
	WebhookURL string `json:"webhook_url"`
}

// Load reads and parses the sentinel config from a JSON file.
// Environment variable references like ${VAR} are expanded.
func Load(path string) (*SentinelConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	var cfg SentinelConfig
	if err := json.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}

// Defaults fills in zero-value fields with sensible defaults.
func (c *SentinelConfig) Defaults() {
	if c.Supervisor.PollIntervalSec == 0 {
		c.Supervisor.PollIntervalSec = 30
	}
	if c.Fixer.SocketPath == "" {
		c.Fixer.SocketPath = "/var/run/sentinel/fixer.sock"
	}
	s := &c.Fixer.Safety
	if s.MaxRequeuesPerJobPerHour == 0 {
		s.MaxRequeuesPerJobPerHour = 3
	}
	if s.MaxRequeuesPerStageTotal == 0 {
		s.MaxRequeuesPerStageTotal = 5
	}
	if s.RestartCooldownSec == 0 {
		s.RestartCooldownSec = 300
	}
	if s.MaxRestartsPerHour == 0 {
		s.MaxRestartsPerHour = 3
	}
}
