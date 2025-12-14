package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/harden"
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
	
	// Baseline hardening flag
	runBaseline := flag.Bool("baseline", false, "run baseline hardening script (outside TUI, interactive prompts)")
	baselineAuto := flag.Bool("baseline-auto", false, "run baseline hardening with all defaults (no prompts)")
	
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

	// Handle baseline hardening (runs outside TUI)
	if *runBaseline || *baselineAuto {
		runBaselineHardening(*baselineAuto)
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

// runBaselineHardening runs the baseline hardening script outside the TUI.
func runBaselineHardening(auto bool) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    IRONGUARD v" + version + "                          ║")
	fmt.Println("║              Baseline Hardening Script                       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	
	// Check for admin privileges
	if !isAdmin() {
		fmt.Println("ERROR: Baseline hardening requires administrator/root privileges.")
		if runtime.GOOS == "windows" {
			fmt.Println("Please run as Administrator (right-click -> Run as administrator)")
		} else {
			fmt.Println("Please run with sudo: sudo ./ironguard --baseline")
		}
		os.Exit(1)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	
	var result *harden.BaselineResult
	var err error
	
	if auto {
		// Use all defaults, no prompts
		cfg := harden.DefaultBaselineConfig()
		cfg.Interactive = false
		result, err = harden.RunBaseline(ctx, cfg)
	} else {
		// Interactive mode with prompts
		result, err = harden.RunBaselineInteractive(ctx)
	}
	
	if err != nil {
		fmt.Printf("\nError: %v\n", err)
		os.Exit(1)
	}
	
	// Save results for AI to read later
	if result != nil {
		saveBaselineResults(result)
	}
	
	fmt.Println()
	fmt.Println("Baseline hardening complete!")
	fmt.Println("You can now run 'ironguard' to start the AI assistant.")
	fmt.Println("The AI will know what baseline changes have already been applied.")
}

// saveBaselineResults saves the baseline results to a file for the AI to read.
func saveBaselineResults(result *harden.BaselineResult) {
	// Save to user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	
	configDir := homeDir + "/.ironguard"
	os.MkdirAll(configDir, 0755)
	
	resultsFile := configDir + "/baseline_results.txt"
	content := result.FormatResultsForAI()
	
	os.WriteFile(resultsFile, []byte(content), 0644)
}



