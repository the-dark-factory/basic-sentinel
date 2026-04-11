package remedy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"sentinel/internal/protocol"
)

// AlertDispatcher sends alerts through multiple channels.
type AlertDispatcher struct {
	LogPath    string
	WebhookURL string
}

// Alert represents a structured alert for dispatch.
type Alert struct {
	Severity  protocol.Severity `json:"severity"`
	CheckName string            `json:"check_name"`
	Summary   string            `json:"summary"`
	Detail    string            `json:"detail"`
	Timestamp string            `json:"timestamp"`
	Action    string            `json:"action_taken"`
	Success   bool              `json:"action_success"`
}

// Dispatch sends an alert to all configured channels.
func (d *AlertDispatcher) Dispatch(alert Alert) {
	if d.LogPath != "" {
		d.writeLog(alert)
	}
	if d.WebhookURL != "" {
		d.sendWebhook(alert)
	}
}

func (d *AlertDispatcher) writeLog(alert Alert) {
	f, err := os.OpenFile(d.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("alert: failed to open log %s: %v", d.LogPath, err)
		return
	}
	defer f.Close()

	data, _ := json.Marshal(alert)
	fmt.Fprintf(f, "%s\n", data)
}

func (d *AlertDispatcher) sendWebhook(alert Alert) {
	payload := map[string]any{
		"text": fmt.Sprintf("[%s] %s: %s", alert.Severity, alert.CheckName, alert.Summary),
		"blocks": []map[string]any{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("Sentinel Alert: %s", alert.CheckName),
				},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Severity:* %s", alert.Severity)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Check:* %s", alert.CheckName)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Summary:* %s", alert.Summary)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Action:* %s (success=%v)", alert.Action, alert.Success)},
				},
			},
		},
	}

	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(d.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("alert: webhook failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("alert: webhook returned HTTP %d", resp.StatusCode)
	}
}
