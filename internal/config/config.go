package config

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

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
	// CompModeCisco is for Cisco challenges (Packet Tracer and NetAcad quizzes).
	CompModeCisco CompetitionMode = "cisco"
	// Legacy aliases for backward compatibility
	CompModePacketTracer CompetitionMode = "cisco" // Alias for cisco mode
	CompModeNetworkQuiz  CompetitionMode = "cisco" // Alias for cisco mode
)

// OSType represents the detected operating system type.
type OSType string

const (
	OSTypeWindows10     OSType = "windows10"
	OSTypeWindows11     OSType = "windows11"
	OSTypeWindowsServer OSType = "windows-server"
	OSTypeUbuntu        OSType = "ubuntu"
	OSTypeDebian        OSType = "debian"
	OSTypeLinuxMint     OSType = "linux-mint"
	OSTypeFedora        OSType = "fedora"
	OSTypeCentOS        OSType = "centos"
	OSTypeLinuxOther    OSType = "linux-other"
	OSTypeUnknown       OSType = "unknown"
)

// OSInfo contains detailed operating system information.
type OSInfo struct {
	Type         OSType // Detected OS type
	Name         string // Human-readable name (e.g., "Ubuntu 22.04 LTS")
	Version      string // Version string (e.g., "22.04", "10.0.19045")
	IsServer     bool   // True if this is a server OS
	Architecture string // CPU architecture (amd64, arm64, etc.)
	Hostname     string // Computer hostname
	Kernel       string // Kernel version (Linux only)
}

// SummarizeMode controls how context summarization is performed.
type SummarizeMode string

const (
	// SummarizeSmart uses an LLM to intelligently summarize context (default).
	SummarizeSmart SummarizeMode = "smart"
	// SummarizeFast uses programmatic extraction (saves tokens).
	SummarizeFast SummarizeMode = "fast"
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
	CompactMode bool // When true, AI gives brief responses

	// Context management
	SummarizeMode SummarizeMode

	// Sound settings
	NoSound         bool // Disable all sound effects
	NoRepeatSound   bool // Play single ding instead of multiple for points gained
	OfficialSound   bool // Use official CyberPatriot gain.wav instead of custom mp3

	// Checkpoint settings
	FreshCheckpoints bool // Start with fresh checkpoints (ignore saved state)

	// Admin/privilege status
	RunningAsAdmin    bool // Whether running with admin/root privileges
	AdminCheckSkipped bool // Whether user used --no-admin flag

	// Environment detection (basic)
	OS           string
	Architecture string

	// Detailed OS info (populated by DetectOS)
	OSInfo OSInfo
}

// DefaultConfig returns the configuration optimized for CyberPatriot competition.
// Uses the most powerful model and autopilot mode for autonomous operation.
func DefaultConfig() Config {
	return Config{
		Provider:      ProviderAnthropic,
		Model:         "claude-opus-4-5", // Most powerful model for competition
		Mode:          ModeAutopilot,     // Autopilot for autonomous operation
		ScreenMode:    ScreenModeObserve, // Observe by default, user can enable control
		CompMode:      CompModeHarden,    // Default to hardening mode
		LogVerbose:    false,
		CompactMode:   false,             // Verbose by default
		SummarizeMode: SummarizeSmart,    // Smart LLM summarization by default
		OS:            runtime.GOOS,
		Architecture:  runtime.GOARCH,
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

// DetectOS detects detailed information about the operating system.
func DetectOS() OSInfo {
	info := OSInfo{
		Type:         OSTypeUnknown,
		Architecture: runtime.GOARCH,
	}

	// Get hostname
	if out, err := exec.Command("hostname").Output(); err == nil {
		info.Hostname = strings.TrimSpace(string(out))
	}

	switch runtime.GOOS {
	case "windows":
		info = detectWindows(info)
	case "linux":
		info = detectLinux(info)
	default:
		info.Name = runtime.GOOS
	}

	return info
}

// detectWindows detects Windows version and type.
func detectWindows(info OSInfo) OSInfo {
	// Use systeminfo or wmic to get Windows version
	out, err := exec.Command("cmd", "/c", "wmic os get Caption,Version,BuildNumber /value").Output()
	if err != nil {
		// Fallback to ver command
		out, _ = exec.Command("cmd", "/c", "ver").Output()
		info.Name = strings.TrimSpace(string(out))
		info.Type = OSTypeWindows10 // Assume Windows 10 as fallback
		return info
	}

	output := string(out)
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Caption=") {
			info.Name = strings.TrimPrefix(line, "Caption=")
		} else if strings.HasPrefix(line, "Version=") {
			info.Version = strings.TrimPrefix(line, "Version=")
		} else if strings.HasPrefix(line, "BuildNumber=") {
			build := strings.TrimPrefix(line, "BuildNumber=")
			info.Version = build
		}
	}

	// Determine OS type from name
	nameLower := strings.ToLower(info.Name)
	if strings.Contains(nameLower, "server") {
		info.Type = OSTypeWindowsServer
		info.IsServer = true
	} else if strings.Contains(nameLower, "11") || (info.Version != "" && compareBuild(info.Version, "22000") >= 0) {
		info.Type = OSTypeWindows11
	} else {
		info.Type = OSTypeWindows10
	}

	return info
}

// detectLinux detects Linux distribution and version.
func detectLinux(info OSInfo) OSInfo {
	// Try /etc/os-release first (most modern distros) - use os.ReadFile instead of exec
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		return parseOSRelease(string(content), info)
	}

	// Fallback to lsb_release
	out, err := exec.Command("lsb_release", "-a").Output()
	if err == nil {
		return parseLSBRelease(string(out), info)
	}

	// Last resort: check for specific files using os.Stat instead of exec
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		info.Type = OSTypeDebian
		info.Name = "Debian"
	} else if _, err := os.Stat("/etc/redhat-release"); err == nil {
		info.Type = OSTypeCentOS
		info.Name = "CentOS/RHEL"
	} else {
		info.Type = OSTypeLinuxOther
		info.Name = "Linux"
	}

	// Get kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	return info
}

// parseOSRelease parses /etc/os-release content.
func parseOSRelease(content string, info OSInfo) OSInfo {
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			info.Name = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			info.Version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		} else if strings.HasPrefix(line, "ID=") {
			id := strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			switch id {
			case "ubuntu":
				info.Type = OSTypeUbuntu
			case "debian":
				info.Type = OSTypeDebian
			case "linuxmint":
				info.Type = OSTypeLinuxMint
			case "fedora":
				info.Type = OSTypeFedora
			case "centos", "rhel":
				info.Type = OSTypeCentOS
			default:
				info.Type = OSTypeLinuxOther
			}
		}
	}

	// Get kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	return info
}

// parseLSBRelease parses lsb_release output.
func parseLSBRelease(content string, info OSInfo) OSInfo {
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		if strings.HasPrefix(line, "Description:") {
			info.Name = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
		} else if strings.HasPrefix(line, "Release:") {
			info.Version = strings.TrimSpace(strings.TrimPrefix(line, "Release:"))
		} else if strings.HasPrefix(line, "Distributor ID:") {
			id := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Distributor ID:")))
			switch id {
			case "ubuntu":
				info.Type = OSTypeUbuntu
			case "debian":
				info.Type = OSTypeDebian
			case "linuxmint":
				info.Type = OSTypeLinuxMint
			case "fedora":
				info.Type = OSTypeFedora
			case "centos":
				info.Type = OSTypeCentOS
			default:
				info.Type = OSTypeLinuxOther
			}
		}
	}

	// Get kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	return info
}

// compareBuild compares Windows build numbers.
func compareBuild(a, b string) int {
	aNum := 0
	bNum := 0
	for _, c := range a {
		if c >= '0' && c <= '9' {
			aNum = aNum*10 + int(c-'0')
		} else {
			break
		}
	}
	for _, c := range b {
		if c >= '0' && c <= '9' {
			bNum = bNum*10 + int(c-'0')
		} else {
			break
		}
	}
	if aNum < bNum {
		return -1
	} else if aNum > bNum {
		return 1
	}
	return 0
}

// OSTypeString returns a human-readable description of the OS type.
func (t OSType) String() string {
	switch t {
	case OSTypeWindows10:
		return "Windows 10"
	case OSTypeWindows11:
		return "Windows 11"
	case OSTypeWindowsServer:
		return "Windows Server"
	case OSTypeUbuntu:
		return "Ubuntu"
	case OSTypeDebian:
		return "Debian"
	case OSTypeLinuxMint:
		return "Linux Mint"
	case OSTypeFedora:
		return "Fedora"
	case OSTypeCentOS:
		return "CentOS/RHEL"
	case OSTypeLinuxOther:
		return "Linux"
	default:
		return "Unknown"
	}
}
