package observe

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"sync"
	"time"

	"sentinel/internal/config"
	"sentinel/internal/protocol"
)

// Observer runs the Supervisor's check loop.
type Observer struct {
	identity *protocol.Identity
	cfg      config.SupervisorConfig
	alertCfg config.AlertConfig
	fixerSock string

	mu       sync.Mutex
	lastReport *protocol.ObservationReport
}

// New creates a new Observer.
func New(identity *protocol.Identity, cfg config.SupervisorConfig, alertCfg config.AlertConfig, fixerSock string) *Observer {
	return &Observer{
		identity:  identity,
		cfg:       cfg,
		alertCfg:  alertCfg,
		fixerSock: fixerSock,
	}
}

// Run starts the observation loop. Blocks until ctx is cancelled.
func (o *Observer) Run(ctx context.Context) {
	log.Printf("supervisor: starting observation loop (%s interval, %d checks)",
		o.cfg.PollInterval(), len(o.cfg.Checks))

	ticker := time.NewTicker(o.cfg.PollInterval())
	defer ticker.Stop()

	// Run immediately on start
	o.cycle()

	for {
		select {
		case <-ctx.Done():
			log.Println("supervisor: shutting down")
			return
		case <-ticker.C:
			o.cycle()
		}
	}
}

// cycle runs all checks once and dispatches findings.
func (o *Observer) cycle() {
	report := &protocol.ObservationReport{
		CycleID:   protocol.NewID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	allHealthy := true
	for _, check := range o.cfg.Checks {
		result := RunCheck(o.identity, check)
		if !result.Healthy && result.Finding != nil {
			report.Findings = append(report.Findings, *result.Finding)
			allHealthy = false
			log.Printf("supervisor: [%s] %s — %s", result.Finding.Severity, result.Finding.CheckName, result.Finding.Summary)

			// If a remediation action is configured, send instruction to fixer
			if check.RemediationAction != "" {
				o.sendInstruction(result.Finding, check.RemediationAction, check.RemediationParams)
			}
		}
	}
	report.AllHealthy = allHealthy

	o.mu.Lock()
	o.lastReport = report
	o.mu.Unlock()

	if allHealthy {
		log.Printf("supervisor: cycle %s — all %d checks healthy", report.CycleID[:8], len(o.cfg.Checks))
	} else {
		log.Printf("supervisor: cycle %s — %d finding(s)", report.CycleID[:8], len(report.Findings))
	}
}

// sendInstruction sends a signed instruction to the Fixer via Unix socket.
func (o *Observer) sendInstruction(finding *protocol.Finding, action, params string) {
	inst := protocol.NewInstruction(o.identity, finding.ID, action, params)

	data, err := protocol.MarshalInstruction(inst)
	if err != nil {
		log.Printf("supervisor: failed to marshal instruction: %v", err)
		return
	}

	conn, err := net.DialTimeout("unix", o.fixerSock, 5*time.Second)
	if err != nil {
		log.Printf("supervisor: fixer unreachable at %s: %v", o.fixerSock, err)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send instruction (newline-delimited JSON)
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		log.Printf("supervisor: failed to send instruction: %v", err)
		return
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("supervisor: no response from fixer: %v", err)
		return
	}

	var result protocol.ActionResult
	if err := json.Unmarshal(buf[:n], &result); err != nil {
		log.Printf("supervisor: invalid fixer response: %v", err)
		return
	}

	if result.Success {
		log.Printf("supervisor: fixer executed %s successfully: %s", result.Action, result.Detail)
	} else {
		log.Printf("supervisor: fixer failed to execute %s: %s", result.Action, result.Detail)
	}
}

// LastReport returns the most recent observation report.
func (o *Observer) LastReport() *protocol.ObservationReport {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastReport
}
