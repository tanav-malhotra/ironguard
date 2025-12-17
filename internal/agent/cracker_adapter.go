package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/tanav-malhotra/ironguard/internal/cracker"
)

// CrackerAdapter manages the scoring engine cracker integration with the agent
type CrackerAdapter struct {
	agent   *Agent
	cracker *cracker.Cracker
	mu      sync.RWMutex
}

// NewCrackerAdapter creates a new cracker adapter for the agent
func NewCrackerAdapter(agent *Agent) *CrackerAdapter {
	return &CrackerAdapter{
		agent:   agent,
		cracker: cracker.New(),
	}
}

// Start begins scoring engine interception
func (ca *CrackerAdapter) Start(ctx context.Context) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Set up callback to inject findings as system messages
	ca.cracker.SetFindingCallback(func(f cracker.Finding) {
		ca.handleFinding(f)
	})

	// Notify AI that cracker is starting
	ca.agent.QueueSystemMessage("[SCORING ENGINE CRACKER] Starting real-time interception...")

	err := ca.cracker.Start(ctx)
	if err != nil {
		return err
	}
	
	// Notify about discovered process (send through event system, not fmt.Printf)
	processName := ca.cracker.GetProcessName()
	pid := ca.cracker.GetPID()
	ca.agent.SendEvent(Event{
		Type:    EventStatusUpdate,
		Content: fmt.Sprintf("[CRACKER] Found scoring engine: %s (PID %d)", processName, pid),
	})
	ca.agent.QueueSystemMessage(fmt.Sprintf("[SCORING ENGINE CRACKER] Found process: %s (PID %d). Now intercepting file/registry access...", processName, pid))
	
	return nil
}

// Stop stops the cracker
func (ca *CrackerAdapter) Stop() {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	
	if ca.cracker != nil {
		ca.cracker.Stop()
	}
}

// IsRunning returns whether the cracker is active
func (ca *CrackerAdapter) IsRunning() bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	
	if ca.cracker == nil {
		return false
	}
	return ca.cracker.IsRunning()
}

// GetFindings returns all discovered findings
func (ca *CrackerAdapter) GetFindings() []cracker.Finding {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	
	if ca.cracker == nil {
		return nil
	}
	return ca.cracker.GetFindings()
}

// GetFormattedFindings returns findings formatted for display
func (ca *CrackerAdapter) GetFormattedFindings() string {
	findings := ca.GetFindings()
	return cracker.FormatAllFindings(findings)
}

// handleFinding processes a new finding and injects it as a system message
func (ca *CrackerAdapter) handleFinding(f cracker.Finding) {
	// Format the finding for AI consumption
	msg := cracker.FormatFindingForAI(f)
	
	// If this is an actionable finding (current != expected), prioritize it
	if f.ExpectedVal != "" && f.CurrentVal != f.ExpectedVal {
		msg = "[SCORING ENGINE - ACTION NEEDED] " + msg
	}
	
	// Queue the finding as a system message for the AI
	ca.agent.QueueSystemMessage(msg)
	
	// Also send an event for the TUI to display
	ca.agent.SendEvent(Event{
		Type:    EventStatusUpdate,
		Content: fmt.Sprintf("[CRACKER] %s: %s", f.Type.String(), f.Path),
	})
}

