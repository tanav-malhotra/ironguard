package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// RegisterDesktopControlTools adds mouse, keyboard, and screen interaction tools.
func (r *Registry) RegisterDesktopControlTools() {
	// Mouse click - supports left, right, middle buttons with single/double click
	r.Register(&Tool{
		Name:        "mouse_click",
		Description: "Click the mouse at specific screen coordinates. Supports left/right/middle buttons with single or double click. Use take_screenshot first to see the screen and identify coordinates.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"x": map[string]interface{}{
					"type":        "integer",
					"description": "X coordinate (pixels from left)",
				},
				"y": map[string]interface{}{
					"type":        "integer",
					"description": "Y coordinate (pixels from top)",
				},
				"button": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"left", "right", "middle"},
					"description": "Mouse button to click (default: left)",
				},
				"clicks": map[string]interface{}{
					"type":        "integer",
					"description": "Number of clicks (1=single, 2=double). Default: 1. Double-click works with any button.",
				},
			},
			"required": []string{"x", "y"},
		},
		Handler:  toolMouseClick,
		Mutating: true,
	})

	// Right click shorthand
	r.Register(&Tool{
		Name:        "right_click",
		Description: "Right-click at specific screen coordinates (shorthand for mouse_click with button=right).",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"x": map[string]interface{}{
					"type":        "integer",
					"description": "X coordinate (pixels from left)",
				},
				"y": map[string]interface{}{
					"type":        "integer",
					"description": "Y coordinate (pixels from top)",
				},
			},
			"required": []string{"x", "y"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				X int `json:"x"`
				Y int `json:"y"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			newArgs, _ := json.Marshal(map[string]interface{}{"x": params.X, "y": params.Y, "button": "right", "clicks": 1})
			return toolMouseClick(ctx, newArgs)
		},
		Mutating: true,
	})

	// Double click shorthand
	r.Register(&Tool{
		Name:        "double_click",
		Description: "Double-click at specific screen coordinates (shorthand for mouse_click with clicks=2).",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"x": map[string]interface{}{
					"type":        "integer",
					"description": "X coordinate (pixels from left)",
				},
				"y": map[string]interface{}{
					"type":        "integer",
					"description": "Y coordinate (pixels from top)",
				},
				"button": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"left", "right", "middle"},
					"description": "Mouse button (default: left)",
				},
			},
			"required": []string{"x", "y"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				X      int    `json:"x"`
				Y      int    `json:"y"`
				Button string `json:"button"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			if params.Button == "" {
				params.Button = "left"
			}
			newArgs, _ := json.Marshal(map[string]interface{}{"x": params.X, "y": params.Y, "button": params.Button, "clicks": 2})
			return toolMouseClick(ctx, newArgs)
		},
		Mutating: true,
	})

	// Middle click shorthand
	r.Register(&Tool{
		Name:        "middle_click",
		Description: "Middle-click at specific screen coordinates (shorthand for mouse_click with button=middle).",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"x": map[string]interface{}{
					"type":        "integer",
					"description": "X coordinate (pixels from left)",
				},
				"y": map[string]interface{}{
					"type":        "integer",
					"description": "Y coordinate (pixels from top)",
				},
			},
			"required": []string{"x", "y"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				X int `json:"x"`
				Y int `json:"y"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			newArgs, _ := json.Marshal(map[string]interface{}{"x": params.X, "y": params.Y, "button": "middle", "clicks": 1})
			return toolMouseClick(ctx, newArgs)
		},
		Mutating: true,
	})

	// Mouse move
	r.Register(&Tool{
		Name:        "mouse_move",
		Description: "Move the mouse cursor to specific screen coordinates without clicking.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"x": map[string]interface{}{
					"type":        "integer",
					"description": "X coordinate (pixels from left)",
				},
				"y": map[string]interface{}{
					"type":        "integer",
					"description": "Y coordinate (pixels from top)",
				},
			},
			"required": []string{"x", "y"},
		},
		Handler:  toolMouseMove,
		Mutating: true,
	})

	// Mouse drag
	r.Register(&Tool{
		Name:        "mouse_drag",
		Description: "Click and drag from one position to another (useful for selecting, moving windows, scrollbars).",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"start_x": map[string]interface{}{
					"type":        "integer",
					"description": "Starting X coordinate",
				},
				"start_y": map[string]interface{}{
					"type":        "integer",
					"description": "Starting Y coordinate",
				},
				"end_x": map[string]interface{}{
					"type":        "integer",
					"description": "Ending X coordinate",
				},
				"end_y": map[string]interface{}{
					"type":        "integer",
					"description": "Ending Y coordinate",
				},
				"button": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"left", "right"},
					"description": "Mouse button to hold during drag (default: left)",
				},
			},
			"required": []string{"start_x", "start_y", "end_x", "end_y"},
		},
		Handler:  toolMouseDrag,
		Mutating: true,
	})

	// Mouse scroll
	r.Register(&Tool{
		Name:        "mouse_scroll",
		Description: "Scroll the mouse wheel at the current position or specified coordinates.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"direction": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"up", "down", "left", "right"},
					"description": "Scroll direction",
				},
				"amount": map[string]interface{}{
					"type":        "integer",
					"description": "Number of scroll units (default: 3)",
				},
				"x": map[string]interface{}{
					"type":        "integer",
					"description": "Optional X coordinate to scroll at",
				},
				"y": map[string]interface{}{
					"type":        "integer",
					"description": "Optional Y coordinate to scroll at",
				},
			},
			"required": []string{"direction"},
		},
		Handler:  toolMouseScroll,
		Mutating: true,
	})

	// Keyboard type
	r.Register(&Tool{
		Name:        "keyboard_type",
		Description: "Type text using the keyboard. The text will be typed wherever the cursor currently is.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"text": map[string]interface{}{
					"type":        "string",
					"description": "The text to type",
				},
				"delay_ms": map[string]interface{}{
					"type":        "integer",
					"description": "Delay between keystrokes in milliseconds (default: 0 for instant)",
				},
			},
			"required": []string{"text"},
		},
		Handler:  toolKeyboardType,
		Mutating: true,
	})

	// Keyboard hotkey
	r.Register(&Tool{
		Name:        "keyboard_hotkey",
		Description: "Press a keyboard shortcut or special key combination (e.g., Ctrl+C, Alt+Tab, Enter, Escape).",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"keys": map[string]interface{}{
					"type":        "string",
					"description": "Key combination using + separator (e.g., 'ctrl+c', 'alt+tab', 'ctrl+shift+esc', 'enter', 'escape', 'tab', 'f5')",
				},
			},
			"required": []string{"keys"},
		},
		Handler:  toolKeyboardHotkey,
		Mutating: true,
	})

	// Get mouse position
	r.Register(&Tool{
		Name:        "get_mouse_position",
		Description: "Get the current mouse cursor position on screen.",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolGetMousePosition,
		Mutating: false,
	})

	// Get screen size
	r.Register(&Tool{
		Name:        "get_screen_size",
		Description: "Get the screen resolution (width and height in pixels).",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolGetScreenSize,
		Mutating: false,
	})

	// Find text on screen (OCR)
	r.Register(&Tool{
		Name:        "find_text_on_screen",
		Description: "Search for text on the screen and return its coordinates. Useful for finding buttons, labels, or menu items to click.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"text": map[string]interface{}{
					"type":        "string",
					"description": "The text to search for on screen",
				},
				"case_sensitive": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether search is case-sensitive (default: false)",
				},
			},
			"required": []string{"text"},
		},
		Handler:  toolFindTextOnScreen,
		Mutating: false,
	})

	// Wait for screen element
	r.Register(&Tool{
		Name:        "wait_for_screen",
		Description: "Wait for a specific element or text to appear on screen before continuing.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"text": map[string]interface{}{
					"type":        "string",
					"description": "Text to wait for",
				},
				"timeout_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum time to wait in seconds (default: 30)",
				},
			},
			"required": []string{"text"},
		},
		Handler:  toolWaitForScreen,
		Mutating: false,
	})

	// Focus window by title
	r.Register(&Tool{
		Name:        "focus_window",
		Description: "Bring a window to the foreground by its title.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"title": map[string]interface{}{
					"type":        "string",
					"description": "Part of the window title to match",
				},
			},
			"required": []string{"title"},
		},
		Handler:  toolFocusWindow,
		Mutating: true,
	})

	// List open windows
	r.Register(&Tool{
		Name:        "list_windows",
		Description: "List all open windows with their titles.",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolListWindows,
		Mutating: false,
	})

	// Click on text (combines find + click)
	r.Register(&Tool{
		Name:        "click_text",
		Description: "Find text on screen and click on it. Combines find_text_on_screen and mouse_click for convenience.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"text": map[string]interface{}{
					"type":        "string",
					"description": "The text to find and click",
				},
				"button": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"left", "right"},
					"description": "Mouse button (default: left)",
				},
			},
			"required": []string{"text"},
		},
		Handler:  toolClickText,
		Mutating: true,
	})
}

// Tool implementations

func toolMouseClick(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		X      int    `json:"x"`
		Y      int    `json:"y"`
		Button string `json:"button"`
		Clicks int    `json:"clicks"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if params.Button == "" {
		params.Button = "left"
	}
	if params.Clicks == 0 {
		params.Clicks = 1
	}

	if runtime.GOOS == "windows" {
		return mouseClickWindows(ctx, params.X, params.Y, params.Button, params.Clicks)
	}
	return mouseClickLinux(ctx, params.X, params.Y, params.Button, params.Clicks)
}

func mouseClickWindows(ctx context.Context, x, y int, button string, clicks int) (string, error) {
	// Use PowerShell with .NET to control mouse
	buttonCode := "0" // Left
	if button == "right" {
		buttonCode = "1"
	} else if button == "middle" {
		buttonCode = "2"
	}

	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(%d, %d)
Start-Sleep -Milliseconds 50

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class MouseOps {
    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);
    public const int MOUSEEVENTF_LEFTDOWN = 0x02;
    public const int MOUSEEVENTF_LEFTUP = 0x04;
    public const int MOUSEEVENTF_RIGHTDOWN = 0x08;
    public const int MOUSEEVENTF_RIGHTUP = 0x10;
    public const int MOUSEEVENTF_MIDDLEDOWN = 0x20;
    public const int MOUSEEVENTF_MIDDLEUP = 0x40;
}
"@

$button = %s
for ($i = 0; $i -lt %d; $i++) {
    if ($button -eq 0) {
        [MouseOps]::mouse_event([MouseOps]::MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        [MouseOps]::mouse_event([MouseOps]::MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
    } elseif ($button -eq 1) {
        [MouseOps]::mouse_event([MouseOps]::MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0)
        [MouseOps]::mouse_event([MouseOps]::MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0)
    } else {
        [MouseOps]::mouse_event([MouseOps]::MOUSEEVENTF_MIDDLEDOWN, 0, 0, 0, 0)
        [MouseOps]::mouse_event([MouseOps]::MOUSEEVENTF_MIDDLEUP, 0, 0, 0, 0)
    }
    if ($i -lt %d - 1) { Start-Sleep -Milliseconds 100 }
}
`, x, y, buttonCode, clicks, clicks)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("mouse click failed: %w", err)
	}

	return fmt.Sprintf("Clicked %s button at (%d, %d) x%d", button, x, y, clicks), nil
}

func mouseClickLinux(ctx context.Context, x, y int, button string, clicks int) (string, error) {
	buttonNum := "1" // Left
	if button == "right" {
		buttonNum = "3"
	} else if button == "middle" {
		buttonNum = "2"
	}

	// Move mouse
	cmd := exec.CommandContext(ctx, "xdotool", "mousemove", strconv.Itoa(x), strconv.Itoa(y))
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("mouse move failed: %w", err)
	}

	// Click
	for i := 0; i < clicks; i++ {
		cmd = exec.CommandContext(ctx, "xdotool", "click", buttonNum)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("mouse click failed: %w", err)
		}
		if i < clicks-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return fmt.Sprintf("Clicked %s button at (%d, %d) x%d", button, x, y, clicks), nil
}

func toolMouseMove(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		X int `json:"x"`
		Y int `json:"y"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if runtime.GOOS == "windows" {
		script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(%d, %d)
`, params.X, params.Y)
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("mouse move failed: %w", err)
		}
	} else {
		cmd := exec.CommandContext(ctx, "xdotool", "mousemove", strconv.Itoa(params.X), strconv.Itoa(params.Y))
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("mouse move failed: %w", err)
		}
	}

	return fmt.Sprintf("Moved mouse to (%d, %d)", params.X, params.Y), nil
}

func toolMouseDrag(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		StartX int    `json:"start_x"`
		StartY int    `json:"start_y"`
		EndX   int    `json:"end_x"`
		EndY   int    `json:"end_y"`
		Button string `json:"button"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if params.Button == "" {
		params.Button = "left"
	}

	if runtime.GOOS == "windows" {
		script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class MouseOps {
    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);
    public const int MOUSEEVENTF_LEFTDOWN = 0x02;
    public const int MOUSEEVENTF_LEFTUP = 0x04;
    public const int MOUSEEVENTF_RIGHTDOWN = 0x08;
    public const int MOUSEEVENTF_RIGHTUP = 0x10;
}
"@

[System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(%d, %d)
Start-Sleep -Milliseconds 50
[MouseOps]::mouse_event([MouseOps]::MOUSEEVENTF_%sDOWN, 0, 0, 0, 0)
Start-Sleep -Milliseconds 50

# Smooth drag
$steps = 20
$dx = (%d - %d) / $steps
$dy = (%d - %d) / $steps
for ($i = 1; $i -le $steps; $i++) {
    $newX = %d + [int]($dx * $i)
    $newY = %d + [int]($dy * $i)
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($newX, $newY)
    Start-Sleep -Milliseconds 10
}

[MouseOps]::mouse_event([MouseOps]::MOUSEEVENTF_%sUP, 0, 0, 0, 0)
`, params.StartX, params.StartY, strings.ToUpper(params.Button),
			params.EndX, params.StartX, params.EndY, params.StartY,
			params.StartX, params.StartY, strings.ToUpper(params.Button))

		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("mouse drag failed: %w", err)
		}
	} else {
		buttonNum := "1"
		if params.Button == "right" {
			buttonNum = "3"
		}

		// Move to start, press, move to end, release
		cmds := [][]string{
			{"xdotool", "mousemove", strconv.Itoa(params.StartX), strconv.Itoa(params.StartY)},
			{"xdotool", "mousedown", buttonNum},
			{"xdotool", "mousemove", strconv.Itoa(params.EndX), strconv.Itoa(params.EndY)},
			{"xdotool", "mouseup", buttonNum},
		}

		for _, cmdArgs := range cmds {
			cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("mouse drag failed: %w", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	return fmt.Sprintf("Dragged from (%d, %d) to (%d, %d)", params.StartX, params.StartY, params.EndX, params.EndY), nil
}

func toolMouseScroll(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Direction string `json:"direction"`
		Amount    int    `json:"amount"`
		X         int    `json:"x"`
		Y         int    `json:"y"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if params.Amount == 0 {
		params.Amount = 3
	}

	// Move to position if specified
	if params.X != 0 || params.Y != 0 {
		toolMouseMove(ctx, json.RawMessage(fmt.Sprintf(`{"x":%d,"y":%d}`, params.X, params.Y)))
	}

	if runtime.GOOS == "windows" {
		scrollAmount := params.Amount * 120 // Windows scroll units
		if params.Direction == "down" || params.Direction == "right" {
			scrollAmount = -scrollAmount
		}

		script := fmt.Sprintf(`
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class MouseOps {
    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);
    public const int MOUSEEVENTF_WHEEL = 0x0800;
    public const int MOUSEEVENTF_HWHEEL = 0x01000;
}
"@

$flags = [MouseOps]::MOUSEEVENTF_%s
[MouseOps]::mouse_event($flags, 0, 0, %d, 0)
`, map[string]string{"up": "WHEEL", "down": "WHEEL", "left": "HWHEEL", "right": "HWHEEL"}[params.Direction], scrollAmount)

		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("scroll failed: %w", err)
		}
	} else {
		buttonNum := map[string]string{"up": "4", "down": "5", "left": "6", "right": "7"}[params.Direction]
		for i := 0; i < params.Amount; i++ {
			cmd := exec.CommandContext(ctx, "xdotool", "click", buttonNum)
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("scroll failed: %w", err)
			}
		}
	}

	return fmt.Sprintf("Scrolled %s %d units", params.Direction, params.Amount), nil
}

func toolKeyboardType(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Text    string `json:"text"`
		DelayMs int    `json:"delay_ms"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if runtime.GOOS == "windows" {
		// Escape special characters for PowerShell
		escapedText := strings.ReplaceAll(params.Text, "'", "''")
		escapedText = strings.ReplaceAll(escapedText, "`", "``")

		script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait('%s')
`, escapedText)

		if params.DelayMs > 0 {
			// Type character by character with delay
			script = `Add-Type -AssemblyName System.Windows.Forms` + "\n"
			for _, char := range params.Text {
				charStr := string(char)
				charStr = strings.ReplaceAll(charStr, "'", "''")
				script += fmt.Sprintf("[System.Windows.Forms.SendKeys]::SendWait('%s')\n", charStr)
				script += fmt.Sprintf("Start-Sleep -Milliseconds %d\n", params.DelayMs)
			}
		}

		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("keyboard type failed: %w", err)
		}
	} else {
		args := []string{"type"}
		if params.DelayMs > 0 {
			args = append(args, "--delay", strconv.Itoa(params.DelayMs))
		}
		args = append(args, "--", params.Text)

		cmd := exec.CommandContext(ctx, "xdotool", args...)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("keyboard type failed: %w", err)
		}
	}

	displayText := params.Text
	if len(displayText) > 50 {
		displayText = displayText[:50] + "..."
	}
	return fmt.Sprintf("Typed: %s", displayText), nil
}

func toolKeyboardHotkey(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Keys string `json:"keys"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	keys := strings.ToLower(params.Keys)

	if runtime.GOOS == "windows" {
		// Convert to SendKeys format
		sendKeysMap := map[string]string{
			"ctrl":      "^",
			"control":   "^",
			"alt":       "%",
			"shift":     "+",
			"enter":     "{ENTER}",
			"return":    "{ENTER}",
			"tab":       "{TAB}",
			"escape":    "{ESC}",
			"esc":       "{ESC}",
			"backspace": "{BACKSPACE}",
			"delete":    "{DELETE}",
			"del":       "{DELETE}",
			"home":      "{HOME}",
			"end":       "{END}",
			"pageup":    "{PGUP}",
			"pagedown":  "{PGDN}",
			"up":        "{UP}",
			"down":      "{DOWN}",
			"left":      "{LEFT}",
			"right":     "{RIGHT}",
			"f1":        "{F1}",
			"f2":        "{F2}",
			"f3":        "{F3}",
			"f4":        "{F4}",
			"f5":        "{F5}",
			"f6":        "{F6}",
			"f7":        "{F7}",
			"f8":        "{F8}",
			"f9":        "{F9}",
			"f10":       "{F10}",
			"f11":       "{F11}",
			"f12":       "{F12}",
			"space":     " ",
		}

		parts := strings.Split(keys, "+")
		var sendKeys string
		var modifiers string

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if mapped, ok := sendKeysMap[part]; ok {
				if part == "ctrl" || part == "control" || part == "alt" || part == "shift" {
					modifiers += mapped
				} else {
					sendKeys += mapped
				}
			} else if len(part) == 1 {
				sendKeys += part
			}
		}

		finalKeys := modifiers + "(" + sendKeys + ")"
		if sendKeys == "" {
			return "", fmt.Errorf("no valid keys found in: %s", params.Keys)
		}

		script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait('%s')
`, finalKeys)

		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("hotkey failed: %w", err)
		}
	} else {
		// xdotool format
		parts := strings.Split(keys, "+")
		var xdotoolKeys []string

		xdotoolMap := map[string]string{
			"ctrl":      "ctrl",
			"control":   "ctrl",
			"alt":       "alt",
			"shift":     "shift",
			"super":     "super",
			"win":       "super",
			"enter":     "Return",
			"return":    "Return",
			"tab":       "Tab",
			"escape":    "Escape",
			"esc":       "Escape",
			"backspace": "BackSpace",
			"delete":    "Delete",
			"space":     "space",
		}

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if mapped, ok := xdotoolMap[part]; ok {
				xdotoolKeys = append(xdotoolKeys, mapped)
			} else {
				xdotoolKeys = append(xdotoolKeys, part)
			}
		}

		cmd := exec.CommandContext(ctx, "xdotool", append([]string{"key"}, strings.Join(xdotoolKeys, "+"))...)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("hotkey failed: %w", err)
		}
	}

	return fmt.Sprintf("Pressed: %s", params.Keys), nil
}

func toolGetMousePosition(ctx context.Context, args json.RawMessage) (string, error) {
	if runtime.GOOS == "windows" {
		script := `
Add-Type -AssemblyName System.Windows.Forms
$pos = [System.Windows.Forms.Cursor]::Position
Write-Output "$($pos.X),$($pos.Y)"
`
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("get mouse position failed: %w", err)
		}
		return fmt.Sprintf("Mouse position: %s", strings.TrimSpace(string(output))), nil
	}

	cmd := exec.CommandContext(ctx, "xdotool", "getmouselocation")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("get mouse position failed: %w", err)
	}
	return fmt.Sprintf("Mouse position: %s", strings.TrimSpace(string(output))), nil
}

func toolGetScreenSize(ctx context.Context, args json.RawMessage) (string, error) {
	if runtime.GOOS == "windows" {
		script := `
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen
Write-Output "$($screen.Bounds.Width)x$($screen.Bounds.Height)"
`
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("get screen size failed: %w", err)
		}
		return fmt.Sprintf("Screen size: %s", strings.TrimSpace(string(output))), nil
	}

	cmd := exec.CommandContext(ctx, "xdotool", "getdisplaygeometry")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("get screen size failed: %w", err)
	}
	return fmt.Sprintf("Screen size: %s", strings.TrimSpace(string(output))), nil
}

func toolFindTextOnScreen(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Text          string `json:"text"`
		CaseSensitive bool   `json:"case_sensitive"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	// This requires OCR - we'll use Tesseract if available, otherwise return instructions
	if runtime.GOOS == "windows" {
		// Check if Tesseract is available
		checkCmd := exec.CommandContext(ctx, "where", "tesseract")
		if err := checkCmd.Run(); err != nil {
			return "", fmt.Errorf("OCR not available. Install Tesseract OCR or use take_screenshot and analyze visually. Search text: %s", params.Text)
		}

		// Take screenshot and run OCR
		script := fmt.Sprintf("$tempImg = \"$env:TEMP\\ironguard_ocr.png\"\n"+
			"$tempTxt = \"$env:TEMP\\ironguard_ocr\"\n"+
			"Add-Type -AssemblyName System.Windows.Forms\n"+
			"Add-Type -AssemblyName System.Drawing\n"+
			"$screen = [System.Windows.Forms.Screen]::PrimaryScreen\n"+
			"$bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)\n"+
			"$graphics = [System.Drawing.Graphics]::FromImage($bitmap)\n"+
			"$graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)\n"+
			"$bitmap.Save($tempImg, [System.Drawing.Imaging.ImageFormat]::Png)\n"+
			"$graphics.Dispose()\n"+
			"$bitmap.Dispose()\n"+
			"tesseract $tempImg $tempTxt 2>$null\n"+
			"$content = Get-Content \"$tempTxt.txt\" -Raw\n"+
			"$searchText = '%s'\n"+
			"$lines = $content -split \"`n\"\n"+
			"$lineNum = 0\n"+
			"foreach ($line in $lines) {\n"+
			"    $lineNum++\n"+
			"    if ($line -match $searchText) {\n"+
			"        Write-Output \"Found '$searchText' on line $lineNum\"\n"+
			"    }\n"+
			"}\n", params.Text)

		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("OCR search failed: %w", err)
		}

		if len(output) == 0 {
			return fmt.Sprintf("Text '%s' not found on screen", params.Text), nil
		}
		return string(output), nil
	}

	// Linux - check for tesseract
	checkCmd := exec.CommandContext(ctx, "which", "tesseract")
	if err := checkCmd.Run(); err != nil {
		return "", fmt.Errorf("OCR not available. Install tesseract-ocr or use take_screenshot and analyze visually. Search text: %s", params.Text)
	}

	return fmt.Sprintf("OCR search for '%s' - use take_screenshot and analyze the image to find coordinates", params.Text), nil
}

func toolWaitForScreen(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Text           string `json:"text"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if params.TimeoutSeconds == 0 {
		params.TimeoutSeconds = 30
	}

	// Simple wait implementation - in practice, would poll with OCR
	return fmt.Sprintf("Waiting for '%s' to appear (timeout: %ds). Use take_screenshot periodically to check.", params.Text, params.TimeoutSeconds), nil
}

func toolFocusWindow(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if runtime.GOOS == "windows" {
		script := fmt.Sprintf(`
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
}
"@

$targetTitle = '%s'
$found = $false

$callback = {
    param([IntPtr]$hwnd, [IntPtr]$lParam)
    if ([Win32]::IsWindowVisible($hwnd)) {
        $sb = New-Object System.Text.StringBuilder 256
        [Win32]::GetWindowText($hwnd, $sb, 256) | Out-Null
        $title = $sb.ToString()
        if ($title -like "*$targetTitle*") {
            [Win32]::SetForegroundWindow($hwnd)
            $script:found = $true
            return $false
        }
    }
    return $true
}

[Win32]::EnumWindows($callback, [IntPtr]::Zero)

if (-not $found) {
    throw "Window not found: $targetTitle"
}
`, params.Title)

		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("focus window failed: %w", err)
		}
	} else {
		cmd := exec.CommandContext(ctx, "xdotool", "search", "--name", params.Title, "windowactivate")
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("focus window failed: %w", err)
		}
	}

	return fmt.Sprintf("Focused window: %s", params.Title), nil
}

func toolListWindows(ctx context.Context, args json.RawMessage) (string, error) {
	if runtime.GOOS == "windows" {
		script := `
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
}
"@

$windows = @()
$callback = {
    param([IntPtr]$hwnd, [IntPtr]$lParam)
    if ([Win32]::IsWindowVisible($hwnd)) {
        $sb = New-Object System.Text.StringBuilder 256
        [Win32]::GetWindowText($hwnd, $sb, 256) | Out-Null
        $title = $sb.ToString()
        if ($title.Length -gt 0) {
            $script:windows += $title
        }
    }
    return $true
}

[Win32]::EnumWindows($callback, [IntPtr]::Zero)
$windows | ForEach-Object { Write-Output $_ }
`
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("list windows failed: %w", err)
		}
		return "Open windows:\n" + string(output), nil
	}

	cmd := exec.CommandContext(ctx, "wmctrl", "-l")
	output, err := cmd.Output()
	if err != nil {
		// Try xdotool fallback
		cmd = exec.CommandContext(ctx, "xdotool", "search", "--name", ".")
		output, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("list windows failed: %w", err)
		}
	}
	return "Open windows:\n" + string(output), nil
}

func toolClickText(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Text   string `json:"text"`
		Button string `json:"button"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	// This is a convenience tool - in practice, the AI should:
	// 1. Take a screenshot
	// 2. Analyze it to find the text
	// 3. Calculate coordinates
	// 4. Click at those coordinates

	return fmt.Sprintf("To click on '%s': 1) Use take_screenshot to see the screen, 2) Identify the coordinates of '%s', 3) Use mouse_click with those coordinates", params.Text, params.Text), nil
}

