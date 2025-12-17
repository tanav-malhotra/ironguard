// Package cracker provides real-time scoring engine interception
// to extract what vulnerabilities are being checked.
package cracker

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Finding represents a discovered scoring check
type Finding struct {
	Type        FindingType
	Path        string    // File path, registry key, or process name
	CurrentVal  string    // Current value found
	ExpectedVal string    // Expected value (from heuristics)
	FixHint     string    // Suggested fix
	Timestamp   time.Time
	IsNew       bool      // True if this is a newly discovered check
}

// FindingType categorizes what kind of check was intercepted
type FindingType int

const (
	FindingTypeFile FindingType = iota
	FindingTypeRegistry
	FindingTypeProcess
	FindingTypeKernelParam
	FindingTypeForensics
)

func (t FindingType) String() string {
	switch t {
	case FindingTypeFile:
		return "FILE"
	case FindingTypeRegistry:
		return "REGISTRY"
	case FindingTypeProcess:
		return "PROCESS"
	case FindingTypeKernelParam:
		return "KERNEL"
	case FindingTypeForensics:
		return "FORENSICS"
	default:
		return "UNKNOWN"
	}
}

// Cracker intercepts scoring engine checks in real-time
type Cracker struct {
	mu          sync.RWMutex
	running     bool
	pid         int
	processName string
	findings    []Finding
	seenPaths   map[string]bool // Track what we've already seen
	onFinding   func(Finding)   // Callback for new findings
	cancel      context.CancelFunc
}

// New creates a new Cracker instance
func New() *Cracker {
	return &Cracker{
		findings:  make([]Finding, 0),
		seenPaths: make(map[string]bool),
	}
}

// SetFindingCallback sets a function to call when new findings are discovered
func (c *Cracker) SetFindingCallback(cb func(Finding)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onFinding = cb
}

// Start begins intercepting the scoring engine
func (c *Cracker) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("cracker already running")
	}
	c.running = true
	c.mu.Unlock()

	// Find the scoring engine process
	pid, processName, err := DiscoverScoringEngine()
	if err != nil {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
		return fmt.Errorf("failed to find scoring engine: %w", err)
	}

	c.mu.Lock()
	c.pid = pid
	c.processName = processName
	c.mu.Unlock()

	// NOTE: Don't use fmt.Printf here - it breaks the TUI
	// The adapter sends events through the proper channel

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()

	// Start platform-specific interception
	if runtime.GOOS == "windows" {
		return c.startWindowsInterception(ctx, pid)
	}
	return c.startLinuxInterception(ctx, pid)
}

// GetProcessName returns the discovered scoring engine process name
func (c *Cracker) GetProcessName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.processName
}

// Stop stops the cracker
func (c *Cracker) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.cancel != nil {
		c.cancel()
	}
	c.running = false
}

// IsRunning returns whether the cracker is active
func (c *Cracker) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// GetFindings returns all discovered findings
func (c *Cracker) GetFindings() []Finding {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	result := make([]Finding, len(c.findings))
	copy(result, c.findings)
	return result
}

// GetPID returns the scoring engine PID
func (c *Cracker) GetPID() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pid
}

// addFinding adds a new finding if not already seen
func (c *Cracker) addFinding(f Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we've seen this path before
	key := fmt.Sprintf("%s:%s", f.Type.String(), f.Path)
	if c.seenPaths[key] {
		return
	}
	c.seenPaths[key] = true
	
	f.IsNew = true
	f.Timestamp = time.Now()
	c.findings = append(c.findings, f)

	// Call callback if set
	if c.onFinding != nil {
		go c.onFinding(f)
	}
}

// RunStandalone runs the cracker in standalone console mode
func RunStandalone(ctx context.Context) error {
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println("IRONGUARD SCORING ENGINE CRACKER")
	fmt.Println("Real-time Answer Key Extractor")
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println()

	c := New()
	
	// Set up callback to print findings
	c.SetFindingCallback(func(f Finding) {
		PrintFinding(f)
	})

	fmt.Println("[*] Searching for scoring engine process...")
	
	if err := c.Start(ctx); err != nil {
		return err
	}
	
	// Print discovered process info (OK to use fmt.Printf here - standalone CLI mode)
	fmt.Printf("[*] Found scoring engine: %s (PID %d)\n", c.GetProcessName(), c.GetPID())
	fmt.Println("[*] Intercepting... Press Ctrl+C to stop")
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println("LIVE FINDINGS")
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println()

	// Wait for context cancellation
	<-ctx.Done()
	
	c.Stop()
	
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Printf("[*] Cracker stopped. Found %d unique checks.\n", len(c.GetFindings()))
	
	return nil
}

