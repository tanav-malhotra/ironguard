package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

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

// Stop stops the cracker and saves findings to disk
func (ca *CrackerAdapter) Stop() {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	
	if ca.cracker != nil {
		ca.cracker.Stop()
		// Save findings to disk so AI can see them even after restart
		ca.saveFindings()
	}
}

// SaveFindings persists current findings to disk
// This is called automatically on Stop() and can be called periodically
func (ca *CrackerAdapter) SaveFindings() {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	ca.saveFindings()
}

// saveFindings is the internal method (must hold lock)
func (ca *CrackerAdapter) saveFindings() {
	if ca.cracker == nil {
		return
	}
	
	findings := ca.cracker.GetFindings()
	if len(findings) == 0 {
		return
	}
	
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	
	// Ensure directory exists
	dir := filepath.Join(homeDir, ".ironguard")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	
	// Format findings for storage
	content := fmt.Sprintf("[SCORING ENGINE CRACKER RESULTS]\n")
	content += fmt.Sprintf("Captured at: %s\n", time.Now().Format(time.RFC3339))
	content += fmt.Sprintf("Process: %s (PID %d)\n", ca.cracker.GetProcessName(), ca.cracker.GetPID())
	content += fmt.Sprintf("Total findings: %d\n\n", len(findings))
	content += cracker.FormatAllFindings(findings)
	
	// Write to file
	resultsFile := filepath.Join(dir, "cracker_results.txt")
	os.WriteFile(resultsFile, []byte(content), 0644)
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

