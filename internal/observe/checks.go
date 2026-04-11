// Package observe implements the Supervisor's observation checks.
// Every function here is read-only — no mutations, no side effects beyond HTTP GETs.
package observe

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"sentinel/internal/config"
	"sentinel/internal/protocol"
)

// CheckResult is the outcome of a single check.
type CheckResult struct {
	Finding *protocol.Finding // nil if healthy
	Healthy bool
}

// RunCheck dispatches to the appropriate check implementation based on kind.
func RunCheck(id *protocol.Identity, check config.CheckConfig) CheckResult {
	switch check.Kind {
	case "http":
		return checkHTTP(id, check)
	case "tls":
		return checkTLS(id, check)
	case "process":
		return checkProcess(id, check)
	case "forge_diagnostics":
		return checkForgeDiagnostics(id, check)
	default:
		f := protocol.NewFinding(id, check.Name, protocol.SevWarning,
			fmt.Sprintf("Unknown check kind: %s", check.Kind), "")
		return CheckResult{Finding: f}
	}
}

func checkHTTP(id *protocol.Identity, check config.CheckConfig) CheckResult {
	client := &http.Client{Timeout: check.Timeout()}

	req, err := http.NewRequest("GET", check.URL, nil)
	if err != nil {
		return unhealthy(id, check.Name, protocol.SevCritical,
			fmt.Sprintf("%s: bad URL", check.Name),
			fmt.Sprintf(`{"url":%q,"error":%q}`, check.URL, err.Error()))
	}
	if check.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+check.AuthToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return unhealthy(id, check.Name, protocol.SevCritical,
			fmt.Sprintf("%s unreachable", check.Name),
			fmt.Sprintf(`{"url":%q,"error":%q}`, check.URL, err.Error()))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return unhealthy(id, check.Name, protocol.SevCritical,
			fmt.Sprintf("%s returned HTTP %d", check.Name, resp.StatusCode),
			fmt.Sprintf(`{"url":%q,"status":%d}`, check.URL, resp.StatusCode))
	}

	return CheckResult{Healthy: true}
}

func checkTLS(id *protocol.Identity, check config.CheckConfig) CheckResult {
	// Extract hostname from URL
	host := check.URL
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: check.Timeout()},
		"tcp", host, &tls.Config{})
	if err != nil {
		return unhealthy(id, check.Name, protocol.SevCritical,
			fmt.Sprintf("TLS handshake failed for %s", host),
			fmt.Sprintf(`{"host":%q,"error":%q}`, host, err.Error()))
	}
	defer conn.Close()

	// Check certificate expiry
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		daysLeft := int(time.Until(certs[0].NotAfter).Hours() / 24)
		if daysLeft < 14 {
			sev := protocol.SevWarning
			if daysLeft < 3 {
				sev = protocol.SevCritical
			}
			return unhealthy(id, check.Name, sev,
				fmt.Sprintf("TLS cert for %s expires in %d days", host, daysLeft),
				fmt.Sprintf(`{"host":%q,"expires":%q,"days_left":%d}`,
					host, certs[0].NotAfter.Format(time.RFC3339), daysLeft))
		}
	}

	return CheckResult{Healthy: true}
}

func checkProcess(id *protocol.Identity, check config.CheckConfig) CheckResult {
	cmd := exec.Command("pgrep", "-f", check.ProcessName)
	if err := cmd.Run(); err != nil {
		return unhealthy(id, check.Name, protocol.SevCritical,
			fmt.Sprintf("Process %s not running", check.ProcessName),
			fmt.Sprintf(`{"process":%q}`, check.ProcessName))
	}
	return CheckResult{Healthy: true}
}

func checkFileExists(id *protocol.Identity, check config.CheckConfig) CheckResult {
	info, err := os.Stat(check.URL) // URL field repurposed for file path
	if err != nil {
		return unhealthy(id, check.Name, protocol.SevCritical,
			fmt.Sprintf("File missing: %s", check.URL),
			fmt.Sprintf(`{"path":%q,"error":%q}`, check.URL, err.Error()))
	}
	if info.Size() == 0 {
		return unhealthy(id, check.Name, protocol.SevWarning,
			fmt.Sprintf("File empty: %s", check.URL),
			fmt.Sprintf(`{"path":%q,"size":0}`, check.URL))
	}
	return CheckResult{Healthy: true}
}

// ForgeDiagnostics is the expected response from GET /api/forge/admin/diagnostics.
type ForgeDiagnostics struct {
	StuckJobs      []DiagJob   `json:"stuck_jobs"`
	OrphanedStages []DiagStage `json:"orphaned_stages"`
	QueueDepth     int         `json:"queue_depth"`
	RunningJobs    int         `json:"running_jobs"`
}

type DiagJob struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
	StuckMin  int    `json:"stuck_minutes"`
}

type DiagStage struct {
	ID        string `json:"id"`
	JobID     string `json:"job_id"`
	Stage     string `json:"stage"`
	ClaimedAt string `json:"claimed_at"`
	StuckMin  int    `json:"stuck_minutes"`
}

func checkForgeDiagnostics(id *protocol.Identity, check config.CheckConfig) CheckResult {
	client := &http.Client{Timeout: check.Timeout()}

	req, _ := http.NewRequest("GET", check.URL, nil)
	if check.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+check.AuthToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return unhealthy(id, check.Name, protocol.SevCritical,
			"Forge diagnostics unreachable",
			fmt.Sprintf(`{"url":%q,"error":%q}`, check.URL, err.Error()))
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return unhealthy(id, check.Name, protocol.SevWarning,
			fmt.Sprintf("Forge diagnostics returned HTTP %d", resp.StatusCode),
			fmt.Sprintf(`{"url":%q,"status":%d}`, check.URL, resp.StatusCode))
	}

	body, _ := io.ReadAll(resp.Body)
	var diag ForgeDiagnostics
	if err := json.Unmarshal(body, &diag); err != nil {
		return unhealthy(id, check.Name, protocol.SevWarning,
			"Forge diagnostics returned invalid JSON",
			fmt.Sprintf(`{"error":%q}`, err.Error()))
	}

	// Check for stuck jobs
	var findings []*protocol.Finding
	for _, j := range diag.StuckJobs {
		threshold := check.StuckJobThresholdMin
		if threshold == 0 {
			threshold = 120
		}
		if j.StuckMin >= threshold {
			detail, _ := json.Marshal(j)
			findings = append(findings, protocol.NewFinding(id, "stuck_job", protocol.SevWarning,
				fmt.Sprintf("Job %s stuck in %s for %d min", j.ID, j.Status, j.StuckMin),
				string(detail)))
		}
	}

	// Check for orphaned stages
	for _, s := range diag.OrphanedStages {
		threshold := check.OrphanedStageThresholdMin
		if threshold == 0 {
			threshold = 30
		}
		if s.StuckMin >= threshold {
			detail, _ := json.Marshal(s)
			findings = append(findings, protocol.NewFinding(id, "orphaned_stage", protocol.SevWarning,
				fmt.Sprintf("Stage %s for job %s claimed for %d min", s.Stage, s.JobID, s.StuckMin),
				string(detail)))
		}
	}

	// Check queue depth
	queueWarn := check.QueueDepthWarning
	if queueWarn == 0 {
		queueWarn = 10
	}
	if diag.QueueDepth > queueWarn {
		findings = append(findings, protocol.NewFinding(id, "queue_depth", protocol.SevInfo,
			fmt.Sprintf("Queue depth %d exceeds threshold %d", diag.QueueDepth, queueWarn),
			fmt.Sprintf(`{"depth":%d,"threshold":%d}`, diag.QueueDepth, queueWarn)))
	}

	if len(findings) > 0 {
		// Return the first finding; the observer loop will handle multiple
		return CheckResult{Finding: findings[0], Healthy: false}
	}

	return CheckResult{Healthy: true}
}

func unhealthy(id *protocol.Identity, name string, sev protocol.Severity, summary, detail string) CheckResult {
	return CheckResult{
		Finding: protocol.NewFinding(id, name, sev, summary, detail),
		Healthy: false,
	}
}
