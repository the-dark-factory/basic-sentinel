// Package remedy implements the Fixer's remediation actions with safety constraints.
package remedy

import (
	"fmt"
	"sync"
	"time"

	"sentinel/internal/config"
)

// SafetyGuard enforces rate limits and cooldowns on remediation actions.
type SafetyGuard struct {
	cfg config.SafetyConfig
	mu  sync.Mutex

	// Track action history for rate limiting
	requeues map[string][]time.Time // job_id -> timestamps
	restarts map[string][]time.Time // service_name -> timestamps
	stageTotals map[string]int      // stage_id -> total requeue count
}

func NewSafetyGuard(cfg config.SafetyConfig) *SafetyGuard {
	return &SafetyGuard{
		cfg:         cfg,
		requeues:    make(map[string][]time.Time),
		restarts:    make(map[string][]time.Time),
		stageTotals: make(map[string]int),
	}
}

// CheckRequeue returns an error if requeuing this job would exceed rate limits.
func (s *SafetyGuard) CheckRequeue(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	recent := pruneOld(s.requeues[jobID], cutoff)
	s.requeues[jobID] = recent

	if len(recent) >= s.cfg.MaxRequeuesPerJobPerHour {
		return fmt.Errorf("rate limit: job %s already requeued %d times in the last hour (max %d)",
			jobID, len(recent), s.cfg.MaxRequeuesPerJobPerHour)
	}
	return nil
}

// RecordRequeue records a successful requeue for rate limiting.
func (s *SafetyGuard) RecordRequeue(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requeues[jobID] = append(s.requeues[jobID], time.Now())
}

// CheckStageRequeue returns an error if this stage has been requeued too many times total.
func (s *SafetyGuard) CheckStageRequeue(stageID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stageTotals[stageID] >= s.cfg.MaxRequeuesPerStageTotal {
		return fmt.Errorf("rate limit: stage %s already requeued %d times total (max %d)",
			stageID, s.stageTotals[stageID], s.cfg.MaxRequeuesPerStageTotal)
	}
	return nil
}

// RecordStageRequeue records a successful stage requeue.
func (s *SafetyGuard) RecordStageRequeue(stageID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stageTotals[stageID]++
}

// CheckRestart returns an error if restarting this service would exceed rate limits.
func (s *SafetyGuard) CheckRestart(service string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	recent := pruneOld(s.restarts[service], cutoff)
	s.restarts[service] = recent

	if len(recent) >= s.cfg.MaxRestartsPerHour {
		return fmt.Errorf("rate limit: %s already restarted %d times in the last hour (max %d)",
			service, len(recent), s.cfg.MaxRestartsPerHour)
	}

	// Check cooldown
	if len(recent) > 0 {
		last := recent[len(recent)-1]
		elapsed := time.Since(last)
		if elapsed < s.cfg.RestartCooldown() {
			return fmt.Errorf("cooldown: %s was restarted %s ago (cooldown %s)",
				service, elapsed.Round(time.Second), s.cfg.RestartCooldown())
		}
	}

	return nil
}

// RecordRestart records a successful restart for rate limiting.
func (s *SafetyGuard) RecordRestart(service string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restarts[service] = append(s.restarts[service], time.Now())
}

func pruneOld(times []time.Time, cutoff time.Time) []time.Time {
	var result []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			result = append(result, t)
		}
	}
	return result
}
