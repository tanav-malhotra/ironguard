package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// TimerManager manages async timers that notify the AI when they expire.
type TimerManager interface {
	SetTimer(id string, duration time.Duration, label string)
	CancelTimer(id string) bool
	ListTimers() []TimerInfo
}

// TimerInfo represents an active timer.
type TimerInfo struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	ExpiresAt time.Time `json:"expires_at"`
	Remaining string    `json:"remaining"`
}

// timerManager is the package-level timer manager set by the agent.
var (
	timerManager   TimerManager
	timerManagerMu sync.RWMutex
)

// SetTimerManager sets the timer manager (called by agent on startup).
func SetTimerManager(tm TimerManager) {
	timerManagerMu.Lock()
	defer timerManagerMu.Unlock()
	timerManager = tm
}

// getTimerManager returns the current timer manager.
func getTimerManager() TimerManager {
	timerManagerMu.RLock()
	defer timerManagerMu.RUnlock()
	return timerManager
}

// RegisterTimingTools adds wait and timer tools to the registry.
func (r *Registry) RegisterTimingTools() {
	// Simple blocking wait tool
	r.Register(&Tool{
		Name: "wait",
		Description: `Wait for a specified number of seconds before continuing.
Use this when you need to pause execution, for example:
- Waiting for a service to restart
- Giving time for a configuration change to take effect
- Waiting before re-checking something

NOTE: This BLOCKS execution - the AI cannot do anything else while waiting.
For non-blocking waits, use set_timer instead.`,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Number of seconds to wait (1-300)",
					"minimum":     1,
					"maximum":     300,
				},
				"reason": map[string]interface{}{
					"type":        "string",
					"description": "Brief reason for waiting (for logging purposes)",
				},
			},
			"required": []string{"seconds"},
		},
		Handler:  toolWait,
		Mutating: false,
	})

	// Async timer with notification
	r.Register(&Tool{
		Name: "set_timer",
		Description: `Set a timer that notifies you when it expires, while you continue working.
Unlike 'wait', this does NOT block - you can continue working on other tasks.
When the timer expires, you'll receive a [SYSTEM] notification.

PERFECT FOR:
- CyberPatriot scoring engine checks (set 90-120s timer, continue working, check score when notified)
- Waiting for updates to install while doing other hardening
- Any case where you want to check something later without blocking

STRATEGY FOR SCORING ENGINE:
The CyberPatriot scoring engine has a 1-2 minute delay. Instead of waiting:
1. Make your fix
2. set_timer(seconds=90, label="check score after [fix description]")
3. Continue working on next task
4. When notified, check score to verify fix worked`,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Number of seconds until timer expires (1-600)",
					"minimum":     1,
					"maximum":     600,
				},
				"label": map[string]interface{}{
					"type":        "string",
					"description": "Label for this timer (e.g., 'check score after disabling guest'). Appears in the notification.",
				},
			},
			"required": []string{"seconds", "label"},
		},
		Handler:  toolSetTimer,
		Mutating: false,
	})

	// List active timers
	r.Register(&Tool{
		Name:        "list_timers",
		Description: "List all active timers and their remaining time.",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolListTimers,
		Mutating: false,
	})

	// Cancel a timer
	r.Register(&Tool{
		Name:        "cancel_timer",
		Description: "Cancel an active timer by its ID.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"timer_id": map[string]interface{}{
					"type":        "string",
					"description": "The ID of the timer to cancel (from list_timers)",
				},
			},
			"required": []string{"timer_id"},
		},
		Handler:  toolCancelTimer,
		Mutating: false,
	})
}

func toolWait(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Seconds int    `json:"seconds"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	// Validate seconds
	if params.Seconds < 1 {
		params.Seconds = 1
	}
	if params.Seconds > 300 {
		params.Seconds = 300
	}

	reasonStr := ""
	if params.Reason != "" {
		reasonStr = fmt.Sprintf(" (%s)", params.Reason)
	}

	// Create a timer that respects context cancellation
	timer := time.NewTimer(time.Duration(params.Seconds) * time.Second)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return fmt.Sprintf("Wait cancelled after partial wait%s", reasonStr), ctx.Err()
	case <-timer.C:
		return fmt.Sprintf("✓ Waited %d seconds%s. Ready to continue.", params.Seconds, reasonStr), nil
	}
}

func toolSetTimer(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Seconds int    `json:"seconds"`
		Label   string `json:"label"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	// Validate seconds
	if params.Seconds < 1 {
		params.Seconds = 1
	}
	if params.Seconds > 600 {
		params.Seconds = 600
	}

	if params.Label == "" {
		params.Label = "unnamed timer"
	}

	tm := getTimerManager()
	if tm == nil {
		return "", fmt.Errorf("timer manager not initialized - timers are not available")
	}

	// Generate a simple timer ID
	timerID := fmt.Sprintf("timer_%d", time.Now().UnixNano()%100000)
	
	tm.SetTimer(timerID, time.Duration(params.Seconds)*time.Second, params.Label)

	return fmt.Sprintf(`⏱️ Timer set: "%s"
ID: %s
Duration: %d seconds
Expires at: %s

Continue working - you'll receive a [SYSTEM] notification when this timer expires.
No need to wait or check manually.`, 
		params.Label, 
		timerID, 
		params.Seconds,
		time.Now().Add(time.Duration(params.Seconds)*time.Second).Format("15:04:05")), nil
}

func toolListTimers(ctx context.Context, args json.RawMessage) (string, error) {
	tm := getTimerManager()
	if tm == nil {
		return "No timer manager available.", nil
	}

	timers := tm.ListTimers()
	if len(timers) == 0 {
		return "No active timers.", nil
	}

	result := "Active Timers:\n"
	for _, t := range timers {
		result += fmt.Sprintf("  • [%s] %s - expires in %s (at %s)\n", 
			t.ID, t.Label, t.Remaining, t.ExpiresAt.Format("15:04:05"))
	}
	return result, nil
}

func toolCancelTimer(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		TimerID string `json:"timer_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if params.TimerID == "" {
		return "", fmt.Errorf("timer_id is required")
	}

	tm := getTimerManager()
	if tm == nil {
		return "", fmt.Errorf("timer manager not available")
	}

	if tm.CancelTimer(params.TimerID) {
		return fmt.Sprintf("✓ Timer %s cancelled.", params.TimerID), nil
	}
	return fmt.Sprintf("Timer %s not found (may have already expired).", params.TimerID), nil
}

