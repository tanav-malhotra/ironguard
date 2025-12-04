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
	if !*noAdmin && !isAdmin() {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "╔════════════════════════════════════════════════════════════════╗")
		fmt.Fprintln(os.Stderr, "║  ADMINISTRATOR PRIVILEGES REQUIRED                             ║")
		fmt.Fprintln(os.Stderr, "╠════════════════════════════════════════════════════════════════╣")
		fmt.Fprintln(os.Stderr, "║                                                                ║")
		fmt.Fprintln(os.Stderr, "║  IronGuard needs elevated privileges to:                       ║")
		fmt.Fprintln(os.Stderr, "║    • Modify system security settings                           ║")
		fmt.Fprintln(os.Stderr, "║    • Edit protected configuration files                        ║")
		fmt.Fprintln(os.Stderr, "║    • Manage user accounts and permissions                      ║")
		fmt.Fprintln(os.Stderr, "║                                                                ║")
		if runtime.GOOS == "windows" {
			fmt.Fprintln(os.Stderr, "║  Run as Administrator:                                         ║")
			fmt.Fprintln(os.Stderr, "║    Right-click → Run as administrator                          ║")
		} else {
			fmt.Fprintln(os.Stderr, "║  Run with sudo:                                                ║")
			fmt.Fprintln(os.Stderr, "║    sudo ironguard                                              ║")
		}
		fmt.Fprintln(os.Stderr, "║                                                                ║")
		fmt.Fprintln(os.Stderr, "║  To skip this check (not recommended):                         ║")
		fmt.Fprintln(os.Stderr, "║    ironguard --no-admin                                        ║")
		fmt.Fprintln(os.Stderr, "║                                                                ║")
		fmt.Fprintln(os.Stderr, "╚════════════════════════════════════════════════════════════════╝")
		fmt.Fprintln(os.Stderr, "")
		os.Exit(1)
	}

	// Default: start the TUI.
	cfg := config.DefaultConfig()
	cfg.NoSound = *noSound
	cfg.NoRepeatSound = *noRepeatSound
	cfg.OfficialSound = *officialSound
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



