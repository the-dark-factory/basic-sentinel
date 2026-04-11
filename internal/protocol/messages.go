package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Severity levels for findings.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Finding is a single observation from the Supervisor.
// The Supervisor signs each finding — the Fixer verifies before acting.
type Finding struct {
	ID            string   `json:"id"`
	CheckName     string   `json:"check_name"`
	Severity      Severity `json:"severity"`
	Summary       string   `json:"summary"`
	Detail        string   `json:"detail"`
	Timestamp     string   `json:"timestamp"`
	Signature     string   `json:"signature"`
	SignerPubKey  string   `json:"signer_pubkey"`
}

// Instruction is a signed directive from Supervisor to Fixer.
// The Fixer will only execute instructions signed by the trusted Supervisor key.
type Instruction struct {
	ID            string `json:"id"`
	FindingID     string `json:"finding_id"`
	Action        string `json:"action"`
	Parameters    string `json:"parameters"`
	Timestamp     string `json:"timestamp"`
	Signature     string `json:"signature"`
	SignerPubKey  string `json:"signer_pubkey"`
}

// ActionResult is the Fixer's signed record of what it did.
type ActionResult struct {
	InstructionID string `json:"instruction_id"`
	Action        string `json:"action"`
	Success       bool   `json:"success"`
	Detail        string `json:"detail"`
	Timestamp     string `json:"timestamp"`
	Signature     string `json:"signature"`
	SignerPubKey  string `json:"signer_pubkey"`
}

// ObservationReport is the output of one complete check cycle.
type ObservationReport struct {
	CycleID    string    `json:"cycle_id"`
	Findings   []Finding `json:"findings"`
	AllHealthy bool      `json:"all_healthy"`
	Timestamp  string    `json:"timestamp"`
}

func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// signingPayload constructs the canonical byte sequence for signing.
func findingSigningPayload(f *Finding) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		f.ID, f.CheckName, f.Severity, f.Summary, f.Detail, f.Timestamp))
}

func instructionSigningPayload(i *Instruction) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s",
		i.ID, i.FindingID, i.Action, i.Parameters, i.Timestamp))
}

func actionResultSigningPayload(a *ActionResult) []byte {
	return []byte(fmt.Sprintf("%s|%s|%v|%s|%s",
		a.InstructionID, a.Action, a.Success, a.Detail, a.Timestamp))
}

// NewFinding creates and signs a Finding.
func NewFinding(id *Identity, checkName string, severity Severity, summary, detail string) *Finding {
	f := &Finding{
		ID:           NewID(),
		CheckName:    checkName,
		Severity:     severity,
		Summary:      summary,
		Detail:       detail,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		SignerPubKey: id.PubKeyHex(),
	}
	f.Signature = id.Sign(findingSigningPayload(f))
	return f
}

// NewInstruction creates and signs an Instruction tied to a Finding.
func NewInstruction(id *Identity, findingID, action, parameters string) *Instruction {
	i := &Instruction{
		ID:           NewID(),
		FindingID:    findingID,
		Action:       action,
		Parameters:   parameters,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		SignerPubKey: id.PubKeyHex(),
	}
	i.Signature = id.Sign(instructionSigningPayload(i))
	return i
}

// NewActionResult creates and signs an ActionResult.
func NewActionResult(id *Identity, instructionID, action string, success bool, detail string) *ActionResult {
	a := &ActionResult{
		InstructionID: instructionID,
		Action:        action,
		Success:       success,
		Detail:        detail,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		SignerPubKey:  id.PubKeyHex(),
	}
	a.Signature = id.Sign(actionResultSigningPayload(a))
	return a
}

// VerifyFinding checks the Ed25519 signature on a Finding.
func VerifyFinding(f *Finding) (bool, error) {
	return VerifySignature(f.SignerPubKey, f.Signature, findingSigningPayload(f))
}

// VerifyInstruction checks the Ed25519 signature on an Instruction.
func VerifyInstruction(i *Instruction) (bool, error) {
	return VerifySignature(i.SignerPubKey, i.Signature, instructionSigningPayload(i))
}

// VerifyActionResult checks the Ed25519 signature on an ActionResult.
func VerifyActionResult(a *ActionResult) (bool, error) {
	return VerifySignature(a.SignerPubKey, a.Signature, actionResultSigningPayload(a))
}

// VerifyInstructionFrom checks that an Instruction was signed by a specific trusted key.
func VerifyInstructionFrom(i *Instruction, trustedPubKeyHex string) (bool, error) {
	if i.SignerPubKey != trustedPubKeyHex {
		return false, fmt.Errorf("instruction signed by %s, expected %s", i.SignerPubKey, trustedPubKeyHex)
	}
	return VerifyInstruction(i)
}

// Marshal helpers

func MarshalFinding(f *Finding) ([]byte, error)         { return json.Marshal(f) }
func MarshalInstruction(i *Instruction) ([]byte, error)  { return json.Marshal(i) }
func MarshalActionResult(a *ActionResult) ([]byte, error) { return json.Marshal(a) }

func UnmarshalInstruction(data []byte) (*Instruction, error) {
	var i Instruction
	if err := json.Unmarshal(data, &i); err != nil {
		return nil, err
	}
	return &i, nil
}

func UnmarshalActionResult(data []byte) (*ActionResult, error) {
	var a ActionResult
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	return &a, nil
}
