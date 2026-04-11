package protocol

import (
	"os"
	"path/filepath"
	"testing"
)

func tempKeyPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name+".key")
}

func TestLoadOrCreateIdentity(t *testing.T) {
	path := tempKeyPath(t, "test")
	id1, err := LoadOrCreateIdentity(path, "supervisor")
	if err != nil {
		t.Fatal(err)
	}
	if id1.Role != "supervisor" {
		t.Fatalf("expected role supervisor, got %s", id1.Role)
	}

	// Reload same key
	id2, err := LoadOrCreateIdentity(path, "supervisor")
	if err != nil {
		t.Fatal(err)
	}
	if id1.PubKeyHex() != id2.PubKeyHex() {
		t.Fatal("reloaded key has different pubkey")
	}

	// Check .pub file written
	pubData, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal("no .pub file written")
	}
	if string(pubData) != id1.PubKeyHex() {
		t.Fatal(".pub file content mismatch")
	}
}

func TestFindingSignAndVerify(t *testing.T) {
	id, _ := LoadOrCreateIdentity(tempKeyPath(t, "sup"), "supervisor")

	f := NewFinding(id, "spark_vllm", SevCritical, "Spark unreachable", `{"url":"http://192.168.0.170:8000"}`)

	valid, err := VerifyFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("finding signature should be valid")
	}

	// Tamper
	f.Summary = "tampered"
	valid, _ = VerifyFinding(f)
	if valid {
		t.Fatal("tampered finding should fail verification")
	}
}

func TestInstructionSignAndVerify(t *testing.T) {
	id, _ := LoadOrCreateIdentity(tempKeyPath(t, "sup"), "supervisor")

	inst := NewInstruction(id, "finding-123", "restart_ollama", `{"service":"ollama"}`)

	valid, err := VerifyInstruction(inst)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("instruction signature should be valid")
	}
}

func TestInstructionFromTrustedKey(t *testing.T) {
	sup, _ := LoadOrCreateIdentity(tempKeyPath(t, "sup"), "supervisor")
	evil, _ := LoadOrCreateIdentity(tempKeyPath(t, "evil"), "evil")

	inst := NewInstruction(sup, "finding-123", "restart_forge", "{}")

	// Verify from trusted key
	valid, err := VerifyInstructionFrom(inst, sup.PubKeyHex())
	if err != nil || !valid {
		t.Fatal("should accept instruction from trusted supervisor")
	}

	// Reject from untrusted key
	_, err = VerifyInstructionFrom(inst, evil.PubKeyHex())
	if err == nil {
		t.Fatal("should reject instruction signed by untrusted key")
	}
}

func TestActionResultSignAndVerify(t *testing.T) {
	fixer, _ := LoadOrCreateIdentity(tempKeyPath(t, "fixer"), "fixer")

	result := NewActionResult(fixer, "inst-456", "restart_ollama", true, "ollama restarted successfully")

	valid, err := VerifyActionResult(result)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("action result signature should be valid")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	sup, _ := LoadOrCreateIdentity(tempKeyPath(t, "sup"), "supervisor")
	inst := NewInstruction(sup, "f-1", "requeue_stuck_job", `{"job_id":"forge_123"}`)

	data, err := MarshalInstruction(inst)
	if err != nil {
		t.Fatal(err)
	}

	inst2, err := UnmarshalInstruction(data)
	if err != nil {
		t.Fatal(err)
	}
	if inst.ID != inst2.ID || inst.Action != inst2.Action || inst.Signature != inst2.Signature {
		t.Fatal("roundtrip mismatch")
	}

	valid, err := VerifyInstruction(inst2)
	if err != nil || !valid {
		t.Fatal("roundtripped instruction should verify")
	}
}

func TestFullWorkflow(t *testing.T) {
	sup, _ := LoadOrCreateIdentity(tempKeyPath(t, "sup"), "supervisor")
	fixer, _ := LoadOrCreateIdentity(tempKeyPath(t, "fixer"), "fixer")

	// 1. Supervisor observes a problem
	finding := NewFinding(sup, "stuck_jobs", SevWarning,
		"Job forge_abc stuck in coding for 3 hours",
		`{"job_id":"forge_abc","status":"coding","stuck_minutes":180}`)

	// 2. Supervisor creates instruction
	inst := NewInstruction(sup, finding.ID, "requeue_stuck_job", `{"job_id":"forge_abc"}`)

	// 3. Fixer verifies instruction is from trusted supervisor
	valid, err := VerifyInstructionFrom(inst, sup.PubKeyHex())
	if err != nil || !valid {
		t.Fatal("fixer should accept supervisor's instruction")
	}

	// 4. Fixer executes and signs result
	result := NewActionResult(fixer, inst.ID, inst.Action, true, "job forge_abc requeued to status=queued")

	// 5. Verify the full chain
	valid, _ = VerifyFinding(finding)
	if !valid {
		t.Fatal("finding should verify")
	}
	valid, _ = VerifyActionResult(result)
	if !valid {
		t.Fatal("action result should verify")
	}
	if result.InstructionID != inst.ID {
		t.Fatal("result should reference the instruction")
	}
}
