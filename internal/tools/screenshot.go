package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// RegisterScreenshotTools adds screenshot and image tools to the registry.
func (r *Registry) RegisterScreenshotTools() {
	// Take screenshot
	r.Register(&Tool{
		Name:        "take_screenshot",
		Description: "Take a screenshot of the current screen. Returns the screenshot as base64 encoded image data that can be analyzed by vision-capable models.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"region": map[string]interface{}{
					"type":        "string",
					"description": "Optional region to capture: 'full' (entire screen), 'active' (active window). Default is 'full'.",
					"enum":        []string{"full", "active"},
				},
			},
		},
		Handler:  toolTakeScreenshot,
		Mutating: false,
	})

	// Read image file
	r.Register(&Tool{
		Name:        "read_image",
		Description: "Read an image file and return it as base64 encoded data for vision analysis",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the image file",
				},
			},
			"required": []string{"path"},
		},
		Handler:  toolReadImage,
		Mutating: false,
	})

	// Capture window by title
	r.Register(&Tool{
		Name:        "capture_window",
		Description: "Capture a specific window by its title",
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
		Handler:  toolCaptureWindow,
		Mutating: false,
	})
}

func toolTakeScreenshot(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Region string `json:"region"`
	}
	json.Unmarshal(args, &params)

	if params.Region == "" {
		params.Region = "full"
	}

	// Create temp file for screenshot
	tmpDir := os.TempDir()
	timestamp := time.Now().Format("20060102_150405")
	screenshotPath := filepath.Join(tmpDir, fmt.Sprintf("ironguard_screenshot_%s.png", timestamp))

	var err error
	if runtime.GOOS == "windows" {
		err = takeScreenshotWindows(ctx, screenshotPath, params.Region)
	} else {
		err = takeScreenshotLinux(ctx, screenshotPath, params.Region)
	}

	if err != nil {
		return "", fmt.Errorf("failed to take screenshot: %w", err)
	}

	// Read and encode the screenshot
	data, err := os.ReadFile(screenshotPath)
	if err != nil {
		return "", fmt.Errorf("failed to read screenshot: %w", err)
	}

	// Clean up temp file
	os.Remove(screenshotPath)

	// Return base64 encoded image with metadata
	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("[IMAGE:screenshot.png;base64,%s]", encoded), nil
}

func takeScreenshotWindows(ctx context.Context, outputPath, region string) error {
	// Use PowerShell to take screenshot
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)

if ("%s" -eq "active") {
    # Capture active window
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
        [StructLayout(LayoutKind.Sequential)]
        public struct RECT {
            public int Left, Top, Right, Bottom;
        }
    }
"@
    $hwnd = [Win32]::GetForegroundWindow()
    $rect = New-Object Win32+RECT
    [Win32]::GetWindowRect($hwnd, [ref]$rect)
    $bitmap = New-Object System.Drawing.Bitmap(($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top))
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
} else {
    $graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
}

$bitmap.Save('%s', [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bitmap.Dispose()
`, region, outputPath)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Run()
}

func takeScreenshotLinux(ctx context.Context, outputPath, region string) error {
	// Check if running under Wayland
	isWayland := os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("XDG_SESSION_TYPE") == "wayland"

	if isWayland {
		// Wayland screenshot tools (in order of preference)
		waylandTools := []struct {
			name string
			args []string
		}{
			{"grim", []string{outputPath}},                           // Most common Wayland screenshot tool
			{"gnome-screenshot", []string{"-f", outputPath}},         // Works on GNOME Wayland
			{"spectacle", []string{"-b", "-n", "-o", outputPath}},    // KDE
			{"ksnip", []string{"-m", "fullscreen", "-s", outputPath}}, // Cross-platform
		}

		if region == "active" {
			// Active window on Wayland is trickier - some tools support it
			waylandTools = []struct {
				name string
				args []string
			}{
				{"gnome-screenshot", []string{"-w", "-f", outputPath}},
				{"spectacle", []string{"-b", "-a", "-n", "-o", outputPath}},
				// grim needs slurp for region selection, fallback to full screen
				{"grim", []string{outputPath}},
			}
		}

		for _, tool := range waylandTools {
			if _, err := exec.LookPath(tool.name); err == nil {
				cmd := exec.CommandContext(ctx, tool.name, tool.args...)
				if err := cmd.Run(); err == nil {
					return nil
				}
			}
		}

		return fmt.Errorf("no Wayland screenshot tool available (tried grim, gnome-screenshot, spectacle, ksnip). Install grim for best results")
	}

	// X11 screenshot tools
	x11Tools := []struct {
		name string
		args []string
	}{
		{"gnome-screenshot", []string{"-f", outputPath}},
		{"scrot", []string{outputPath}},
		{"import", []string{"-window", "root", outputPath}}, // ImageMagick
		{"maim", []string{outputPath}},
	}

	if region == "active" {
		x11Tools = []struct {
			name string
			args []string
		}{
			{"gnome-screenshot", []string{"-w", "-f", outputPath}},
			{"scrot", []string{"-u", outputPath}},
			{"import", []string{"-window", "$(xdotool getactivewindow)", outputPath}},
			{"maim", []string{"-i", "$(xdotool getactivewindow)", outputPath}},
		}
	}

	for _, tool := range x11Tools {
		if _, err := exec.LookPath(tool.name); err == nil {
			cmd := exec.CommandContext(ctx, tool.name, tool.args...)
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
	}

	return fmt.Errorf("no X11 screenshot tool available (tried gnome-screenshot, scrot, import, maim)")
}

func toolReadImage(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	data, err := os.ReadFile(params.Path)
	if err != nil {
		return "", fmt.Errorf("failed to read image: %w", err)
	}

	// Determine image type from extension
	ext := filepath.Ext(params.Path)
	mimeType := "image/png"
	switch ext {
	case ".jpg", ".jpeg":
		mimeType = "image/jpeg"
	case ".gif":
		mimeType = "image/gif"
	case ".webp":
		mimeType = "image/webp"
	case ".bmp":
		mimeType = "image/bmp"
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("[IMAGE:%s;%s;base64,%s]", filepath.Base(params.Path), mimeType, encoded), nil
}

func toolCaptureWindow(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	tmpDir := os.TempDir()
	timestamp := time.Now().Format("20060102_150405")
	screenshotPath := filepath.Join(tmpDir, fmt.Sprintf("ironguard_window_%s.png", timestamp))

	var err error
	if runtime.GOOS == "windows" {
		err = captureWindowWindows(ctx, screenshotPath, params.Title)
	} else {
		err = captureWindowLinux(ctx, screenshotPath, params.Title)
	}

	if err != nil {
		return "", fmt.Errorf("failed to capture window: %w", err)
	}

	data, err := os.ReadFile(screenshotPath)
	if err != nil {
		return "", fmt.Errorf("failed to read screenshot: %w", err)
	}

	os.Remove(screenshotPath)

	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("[IMAGE:window_%s.png;base64,%s]", params.Title, encoded), nil
}

func captureWindowWindows(ctx context.Context, outputPath, title string) error {
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
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
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left, Top, Right, Bottom;
    }
}
"@

$targetTitle = "%s"
$foundHwnd = [IntPtr]::Zero

$callback = {
    param([IntPtr]$hwnd, [IntPtr]$lParam)
    if ([Win32]::IsWindowVisible($hwnd)) {
        $sb = New-Object System.Text.StringBuilder 256
        [Win32]::GetWindowText($hwnd, $sb, 256) | Out-Null
        $title = $sb.ToString()
        if ($title -like "*$targetTitle*") {
            $script:foundHwnd = $hwnd
            return $false
        }
    }
    return $true
}

[Win32]::EnumWindows($callback, [IntPtr]::Zero)

if ($foundHwnd -eq [IntPtr]::Zero) {
    throw "Window not found: $targetTitle"
}

$rect = New-Object Win32+RECT
[Win32]::GetWindowRect($foundHwnd, [ref]$rect)

$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top

$bitmap = New-Object System.Drawing.Bitmap($width, $height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
$bitmap.Save('%s', [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bitmap.Dispose()
`, title, outputPath)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Run()
}

func captureWindowLinux(ctx context.Context, outputPath, title string) error {
	// Try to find window by title and capture it
	script := fmt.Sprintf(`
WINDOW_ID=$(xdotool search --name "%s" | head -1)
if [ -z "$WINDOW_ID" ]; then
    echo "Window not found: %s"
    exit 1
fi

# Try different screenshot tools
if command -v import &> /dev/null; then
    import -window "$WINDOW_ID" "%s"
elif command -v maim &> /dev/null; then
    maim -i "$WINDOW_ID" "%s"
elif command -v gnome-screenshot &> /dev/null; then
    # Activate window first, then capture
    xdotool windowactivate "$WINDOW_ID"
    sleep 0.5
    gnome-screenshot -w -f "%s"
else
    echo "No screenshot tool available"
    exit 1
fi
`, title, title, outputPath, outputPath, outputPath)

	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	return cmd.Run()
}

