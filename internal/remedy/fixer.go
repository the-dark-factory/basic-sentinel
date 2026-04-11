package remedy

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"sentinel/internal/config"
	"sentinel/internal/protocol"
)

// Fixer listens for signed instructions from the Supervisor and executes them.
type Fixer struct {
	identity       *protocol.Identity
	cfg            config.FixerConfig
	safety         *SafetyGuard
	trustedPubKey  string
	alerts         *AlertDispatcher
}

// New creates a new Fixer.
func New(identity *protocol.Identity, cfg config.FixerConfig) *Fixer {
	return &Fixer{
		identity:      identity,
		cfg:           cfg,
		safety:        NewSafetyGuard(cfg.Safety),
		trustedPubKey: cfg.SupervisorPubKey,
	}
}

// SetAlertDispatcher configures the alert dispatcher for human escalation.
func (f *Fixer) SetAlertDispatcher(d *AlertDispatcher) {
	f.alerts = d
}

// Run starts the Fixer's Unix socket listener. Blocks until ctx is cancelled.
func (f *Fixer) Run(ctx context.Context) error {
	// Remove stale socket
	os.Remove(f.cfg.SocketPath)

	// Ensure parent directory exists
	dir := f.cfg.SocketPath[:strings.LastIndex(f.cfg.SocketPath, "/")]
	os.MkdirAll(dir, 0770)

	listener, err := net.Listen("unix", f.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", f.cfg.SocketPath, err)
	}
	defer listener.Close()

	// Set socket permissions
	os.Chmod(f.cfg.SocketPath, 0660)

	log.Printf("fixer: listening on %s", f.cfg.SocketPath)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			log.Printf("fixer: accept error: %v", err)
			continue
		}
		go f.handleConnection(conn)
	}
}

func (f *Fixer) handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		log.Printf("fixer: empty connection")
		return
	}

	inst, err := protocol.UnmarshalInstruction(scanner.Bytes())
	if err != nil {
		log.Printf("fixer: invalid instruction: %v", err)
		return
	}

	// Verify the instruction is from the trusted Supervisor
	valid, err := protocol.VerifyInstructionFrom(inst, f.trustedPubKey)
	if err != nil || !valid {
		log.Printf("fixer: REJECTED instruction %s — untrusted signer %s", inst.ID[:8], inst.SignerPubKey[:16])
		result := protocol.NewActionResult(f.identity, inst.ID, inst.Action, false, "rejected: untrusted signer")
		data, _ := protocol.MarshalActionResult(result)
		conn.Write(data)
		return
	}

	log.Printf("fixer: accepted instruction %s — action=%s", inst.ID[:8], inst.Action)

	// Execute the action
	result := f.execute(inst)

	data, _ := protocol.MarshalActionResult(result)
	conn.Write(data)
}

func (f *Fixer) execute(inst *protocol.Instruction) *protocol.ActionResult {
	switch inst.Action {
	case "requeue_stuck_job":
		return f.requeueStuckJob(inst)
	case "restart_service":
		return f.restartService(inst)
	case "alert_human":
		return f.alertHuman(inst)
	default:
		return protocol.NewActionResult(f.identity, inst.ID, inst.Action, false,
			fmt.Sprintf("unknown action: %s", inst.Action))
	}
}

func (f *Fixer) requeueStuckJob(inst *protocol.Instruction) *protocol.ActionResult {
	params, err := ParseRequeueParams(inst.Parameters)
	if err != nil {
		return protocol.NewActionResult(f.identity, inst.ID, inst.Action, false, err.Error())
	}

	// Safety check
	if err := f.safety.CheckRequeue(params.JobID); err != nil {
		log.Printf("fixer: safety blocked requeue: %v", err)
		return protocol.NewActionResult(f.identity, inst.ID, inst.Action, false, err.Error())
	}

	// Use the Forge API to requeue (POST to diagnostics/requeue endpoint)
	detail, err := f.forgeRequeue(params.JobID)
	if err != nil {
		return protocol.NewActionResult(f.identity, inst.ID, inst.Action, false, err.Error())
	}

	f.safety.RecordRequeue(params.JobID)
	return protocol.NewActionResult(f.identity, inst.ID, inst.Action, true, detail)
}

func (f *Fixer) restartService(inst *protocol.Instruction) *protocol.ActionResult {
	params, err := ParseRestartParams(inst.Parameters)
	if err != nil {
		return protocol.NewActionResult(f.identity, inst.ID, inst.Action, false, err.Error())
	}

	// Safety check
	if err := f.safety.CheckRestart(params.Service); err != nil {
		log.Printf("fixer: safety blocked restart: %v", err)
		return protocol.NewActionResult(f.identity, inst.ID, inst.Action, false, err.Error())
	}

	var detail string
	if params.Host == "" {
		detail, err = RestartService(params.Service)
	} else {
		detail, err = RestartServiceSSH(params.Host, params.Service, params.KeyPath)
	}
	if err != nil {
		return protocol.NewActionResult(f.identity, inst.ID, inst.Action, false, err.Error())
	}

	f.safety.RecordRestart(params.Service)
	return protocol.NewActionResult(f.identity, inst.ID, inst.Action, true, detail)
}

func (f *Fixer) alertHuman(inst *protocol.Instruction) *protocol.ActionResult {
	log.Printf("fixer: ALERT — %s", inst.Parameters)
	if f.alerts != nil {
		f.alerts.Dispatch(Alert{
			Severity:  protocol.SevCritical,
			CheckName: "escalation",
			Summary:   inst.Parameters,
			Timestamp: inst.Timestamp,
			Action:    "alert_human",
			Success:   true,
		})
	}
	return protocol.NewActionResult(f.identity, inst.ID, inst.Action, true, "alert dispatched")
}

// forgeRequeue calls the Forge API to requeue a stuck job.
func (f *Fixer) forgeRequeue(jobID string) (string, error) {
	url := fmt.Sprintf("%s/api/forge/admin/requeue/%s", f.cfg.ForgeAPIURL, jobID)
	req, _ := http.NewRequest("POST", url, nil)
	if f.cfg.ForgeAPISecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.ForgeAPISecret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("forge requeue API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("forge requeue returned HTTP %d", resp.StatusCode)
	}

	return fmt.Sprintf("job %s requeued via Forge API", jobID), nil
}
