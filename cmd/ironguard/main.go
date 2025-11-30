package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/tui"
)

// version is overridden at build time via -ldflags when building releases.
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print ironguard version and exit")
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

	// Default: start the TUI.
	cfg := config.DefaultConfig()
	if err := tui.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}



