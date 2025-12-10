package agent

import (
	"fmt"
	"sync"
	"time"

	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// TimerManagerAdapter implements tools.TimerManager and bridges to the agent.
type TimerManagerAdapter struct {
	agent  *Agent
	timers map[string]*activeTimer
	mu     sync.RWMutex
}

// activeTimer represents a running timer.
type activeTimer struct {
	ID        string
	Label     string
	ExpiresAt time.Time
	Cancel    chan struct{}
}

// NewTimerManagerAdapter creates a new timer manager that notifies the agent.
func NewTimerManagerAdapter(agent *Agent) *TimerManagerAdapter {
	return &TimerManagerAdapter{
		agent:  agent,
		timers: make(map[string]*activeTimer),
	}
}

// SetTimer starts a timer that will notify the agent when it expires.
func (tm *TimerManagerAdapter) SetTimer(id string, duration time.Duration, label string) {
	tm.mu.Lock()
	
	// Cancel existing timer with same ID if present
	if existing, ok := tm.timers[id]; ok {
		close(existing.Cancel)
		delete(tm.timers, id)
	}
	
	timer := &activeTimer{
		ID:        id,
		Label:     label,
		ExpiresAt: time.Now().Add(duration),
		Cancel:    make(chan struct{}),
	}
	tm.timers[id] = timer
	tm.mu.Unlock()
	
	// Start goroutine to wait and notify
	go func() {
		select {
		case <-time.After(duration):
			// Timer expired - notify the agent
			tm.mu.Lock()
			delete(tm.timers, id)
			tm.mu.Unlock()
			
			notification := fmt.Sprintf(`[SYSTEM] ⏱️ TIMER EXPIRED: "%s"
Timer ID: %s
Duration: %v

This timer was set to remind you to check something. Take appropriate action now.`, 
				label, id, duration.Round(time.Second))
			
			tm.agent.QueueSystemMessage(notification)
			
			// Also send a status event for TUI visibility
			tm.agent.events <- Event{
				Type:    EventStatusUpdate,
				Content: fmt.Sprintf("⏱️ Timer expired: %s", label),
			}
			
		case <-timer.Cancel:
			// Timer was cancelled
			tm.mu.Lock()
			delete(tm.timers, id)
			tm.mu.Unlock()
		}
	}()
}

// CancelTimer cancels an active timer.
func (tm *TimerManagerAdapter) CancelTimer(id string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	if timer, ok := tm.timers[id]; ok {
		close(timer.Cancel)
		delete(tm.timers, id)
		return true
	}
	return false
}

// ListTimers returns all active timers.
func (tm *TimerManagerAdapter) ListTimers() []tools.TimerInfo {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	result := make([]tools.TimerInfo, 0, len(tm.timers))
	now := time.Now()
	
	for _, t := range tm.timers {
		remaining := t.ExpiresAt.Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		
		result = append(result, tools.TimerInfo{
			ID:        t.ID,
			Label:     t.Label,
			ExpiresAt: t.ExpiresAt,
			Remaining: formatDuration(remaining),
		})
	}
	
	return result
}

// formatDuration formats a duration nicely (e.g., "1m 30s").
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	
	if seconds == 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%dm %ds", minutes, seconds)
}

