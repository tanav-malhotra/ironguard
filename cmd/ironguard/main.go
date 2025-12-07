package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/tui"
)

// version is overridden at build time via -ldflags when building releases.
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print ironguard version and exit")
	noAdmin := flag.Bool("no-admin", false, "skip admin/root privilege check (not recommended)")
	noSound := flag.Bool("no-sound", false, "disable all sound effects")
	noRepeatSound := flag.Bool("no-repeat-sound", false, "play single ding instead of multiple for points gained")
	officialSound := flag.Bool("official-sound", false, "use official CyberPatriot sound instead of custom mp3")
	freshCheckpoints := flag.Bool("fresh", false, "start with fresh checkpoints (ignore saved state)")
	
	// Provider selection flags
	useClaude := flag.Bool("claude", false, "start with Claude (Anthropic) as the AI provider")
	useOpenAI := flag.Bool("openai", false, "start with OpenAI (GPT) as the AI provider")
	useGemini := flag.Bool("gemini", false, "start with Gemini (Google) as the AI provider")
	
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "ironguard – CyberPatriot AI helper\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n  ironguard [flags]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("ironguard %s\n", version)
		return
	}

	// Check for admin/root privileges
	runningAsAdmin := isAdmin()
	
	// Default: start the TUI.
	cfg := config.DefaultConfig()
	cfg.NoSound = *noSound
	cfg.NoRepeatSound = *noRepeatSound
	cfg.OfficialSound = *officialSound
	cfg.FreshCheckpoints = *freshCheckpoints
	cfg.RunningAsAdmin = runningAsAdmin
	cfg.AdminCheckSkipped = *noAdmin
	
	// Apply provider selection (last flag wins if multiple specified)
	if *useClaude {
		cfg.Provider = config.ProviderAnthropic
		cfg.Model = "claude-opus-4-5"
	}
	if *useOpenAI {
		cfg.Provider = config.ProviderOpenAI
		cfg.Model = "gpt-5.1"
	}
	if *useGemini {
		cfg.Provider = config.ProviderGemini
		cfg.Model = "gemini-3-pro-preview"
	}
	
	if err := tui.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// isAdmin checks if the current process has administrator/root privileges.
func isAdmin() bool {
	if runtime.GOOS == "windows" {
		return isAdminWindows()
	}
	// Unix: check if running as root (uid 0)
	return os.Geteuid() == 0
}



