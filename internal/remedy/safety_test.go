package remedy

import (
	"strings"
	"testing"
	"time"

	"sentinel/internal/config"
)

func testSafety() *SafetyGuard {
	return NewSafetyGuard(config.SafetyConfig{
		MaxRequeuesPerJobPerHour: 3,
		MaxRequeuesPerStageTotal: 2,
		RestartCooldownSec:       5, // short for tests
		MaxRestartsPerHour:       2,
	})
}

func TestRequeueRateLimit(t *testing.T) {
	s := testSafety()

	// First 3 should pass
	for i := 0; i < 3; i++ {
		if err := s.CheckRequeue("job-1"); err != nil {
			t.Fatalf("requeue %d should be allowed: %v", i+1, err)
		}
		s.RecordRequeue("job-1")
	}

	// 4th should be blocked
	if err := s.CheckRequeue("job-1"); err == nil {
		t.Fatal("4th requeue should be blocked")
	} else if !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("expected rate limit error, got: %v", err)
	}

	// Different job should still be allowed
	if err := s.CheckRequeue("job-2"); err != nil {
		t.Fatalf("different job should be allowed: %v", err)
	}
}

func TestStageRequeueTotal(t *testing.T) {
	s := testSafety()

	s.RecordStageRequeue("stage-1")
	if err := s.CheckStageRequeue("stage-1"); err != nil {
		t.Fatalf("1st stage requeue should be allowed: %v", err)
	}

	s.RecordStageRequeue("stage-1")
	if err := s.CheckStageRequeue("stage-1"); err == nil {
		t.Fatal("3rd stage requeue should be blocked (max 2)")
	}
}

func TestRestartCooldown(t *testing.T) {
	s := testSafety()

	if err := s.CheckRestart("forge"); err != nil {
		t.Fatalf("first restart should be allowed: %v", err)
	}
	s.RecordRestart("forge")

	// Immediate retry should be blocked by cooldown
	if err := s.CheckRestart("forge"); err == nil {
		t.Fatal("restart within cooldown should be blocked")
	} else if !strings.Contains(err.Error(), "cooldown") {
		t.Fatalf("expected cooldown error, got: %v", err)
	}

	// Different service should be allowed
	if err := s.CheckRestart("ollama"); err != nil {
		t.Fatalf("different service should be allowed: %v", err)
	}
}

func TestRestartRateLimit(t *testing.T) {
	s := NewSafetyGuard(config.SafetyConfig{
		MaxRestartsPerHour:  2,
		RestartCooldownSec:  0, // no cooldown for this test
	})

	s.RecordRestart("forge")
	s.RecordRestart("forge")

	if err := s.CheckRestart("forge"); err == nil {
		t.Fatal("3rd restart should be blocked by hourly rate limit")
	} else if !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("expected rate limit error, got: %v", err)
	}
}

func TestPruneOldEntries(t *testing.T) {
	s := testSafety()

	// Manually inject old timestamps
	s.mu.Lock()
	old := time.Now().Add(-2 * time.Hour)
	s.requeues["job-old"] = []time.Time{old, old, old}
	s.mu.Unlock()

	// Should be allowed since old entries are pruned
	if err := s.CheckRequeue("job-old"); err != nil {
		t.Fatalf("old entries should be pruned: %v", err)
	}
}

func TestCooldownExpiry(t *testing.T) {
	s := NewSafetyGuard(config.SafetyConfig{
		MaxRestartsPerHour:  10,
		RestartCooldownSec:  1, // 1 second cooldown
	})

	s.RecordRestart("forge")
	time.Sleep(1100 * time.Millisecond)

	if err := s.CheckRestart("forge"); err != nil {
		t.Fatalf("restart after cooldown should be allowed: %v", err)
	}
}
