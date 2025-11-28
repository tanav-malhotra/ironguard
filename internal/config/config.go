package config

import "runtime"

// Provider represents a logical LLM provider.
type Provider string

const (
	ProviderAnthropic Provider = "claude"
	ProviderOpenAI    Provider = "openai"
	ProviderGemini    Provider = "gemini"
)

// Mode controls how aggressively the agent is allowed to act.
type Mode string

const (
	// ModeConfirm requires confirmation before any mutating action.
	ModeConfirm Mode = "confirm"
	// ModeAutopilot allows the agent to run tools/commands without per-action confirmation.
	ModeAutopilot Mode = "autopilot"
)

// ScreenMode controls how the AI can interact with the desktop.
type ScreenMode string

const (
	// ScreenModeObserve allows AI to view screen but not control mouse/keyboard.
	ScreenModeObserve ScreenMode = "observe"
	// ScreenModeControl allows AI full mouse/keyboard control of the desktop.
	ScreenModeControl ScreenMode = "control"
)

// CompetitionMode specifies which type of competition/task.
type CompetitionMode string

const (
	// CompModeHarden is for CyberPatriot image hardening (Windows/Linux).
	CompModeHarden CompetitionMode = "harden"
	// CompModePacketTracer is for Cisco Packet Tracer challenges.
	CompModePacketTracer CompetitionMode = "packet-tracer"
	// CompModeNetworkQuiz is for networking quizzes (NetAcad, etc.).
	CompModeNetworkQuiz CompetitionMode = "network-quiz"
)

// Config holds the in-memory runtime configuration for ironguard.
// For competition use we intentionally avoid mandatory config files.
type Config struct {
	// LLM settings
	Provider Provider
	Model    string

	// Safety / execution behavior
	Mode Mode

	// Screen interaction mode
	ScreenMode ScreenMode

	// Competition mode
	CompMode CompetitionMode

	// Logging / UX
	LogVerbose bool

	// Environment detection
	OS           string
	Architecture string
}

// DefaultConfig returns the configuration optimized for CyberPatriot competition.
// Uses the most powerful model and autopilot mode for autonomous operation.
func DefaultConfig() Config {
	return Config{
		Provider:     ProviderAnthropic,
		Model:        "claude-opus-4-5", // Most powerful model for competition
		Mode:         ModeAutopilot,     // Autopilot for autonomous operation
		ScreenMode:   ScreenModeObserve, // Observe by default, user can enable control
		CompMode:     CompModeHarden,    // Default to hardening mode
		LogVerbose:   false,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}
}

// ProviderFromString converts a string to a Provider.
func ProviderFromString(s string) Provider {
	switch s {
	case "claude", "anthropic":
		return ProviderAnthropic
	case "openai", "gpt":
		return ProviderOpenAI
	case "gemini", "google":
		return ProviderGemini
	default:
		return ProviderAnthropic
	}
}
