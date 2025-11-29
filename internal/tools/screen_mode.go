package tools

import (
	"sync"

	"github.com/tanav-malhotra/ironguard/internal/config"
)

// Global screen mode state (set by TUI/agent)
var (
	currentScreenMode config.ScreenMode = config.ScreenModeObserve
	screenModeMu      sync.RWMutex
)

// SetScreenMode updates the current screen mode.
func SetScreenMode(mode config.ScreenMode) {
	screenModeMu.Lock()
	defer screenModeMu.Unlock()
	currentScreenMode = mode
}

// GetScreenMode returns the current screen mode.
func GetScreenMode() config.ScreenMode {
	screenModeMu.RLock()
	defer screenModeMu.RUnlock()
	return currentScreenMode
}

// IsScreenControlEnabled returns true if screen control is allowed.
func IsScreenControlEnabled() bool {
	return GetScreenMode() == config.ScreenModeControl
}

// ScreenModeError returns an error message for when screen control is disabled.
func ScreenModeError() string {
	return `⚠️ SCREEN CONTROL DISABLED

This tool requires screen control mode, but it's currently set to OBSERVE.

The user has not enabled screen control. You can:
1. Ask the user to run: /screen control
2. Use alternative tools that don't require screen control
3. Add a manual task for the user to do this GUI action

Current mode: OBSERVE (AI can see screen but cannot control mouse/keyboard)
To enable: User must run "/screen control"

This is a safety feature to prevent accidental mouse/keyboard actions.`
}

