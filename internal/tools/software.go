package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

// RegisterSoftwareTools registers software management tools.
func (r *Registry) RegisterSoftwareTools() {
	r.Register(&Tool{
		Name:        "list_installed_software",
		Description: "List all installed software/packages on the system. Use this to find prohibited software like games, hacking tools, P2P clients, etc.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"filter": map[string]interface{}{
					"type":        "string",
					"description": "Optional filter to search for specific software (e.g., 'game', 'vnc', 'torrent'). Case-insensitive.",
				},
			},
		},
		Handler:  toolListInstalledSoftware,
		Mutating: false,
	})

	r.Register(&Tool{
		Name:        "remove_software",
		Description: "Remove/uninstall software from the system. Use this to remove prohibited software like games, hacking tools, P2P clients, etc.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"package_name": map[string]interface{}{
					"type":        "string",
					"description": "The package/software name to remove (e.g., 'wireshark', 'aisleriot', 'transmission')",
				},
				"purge": map[string]interface{}{
					"type":        "boolean",
					"description": "Linux only: If true, also remove configuration files (apt purge). Default: true",
					"default":     true,
				},
			},
			"required": []string{"package_name"},
		},
		Handler:  toolRemoveSoftware,
		Mutating: true,
	})

	r.Register(&Tool{
		Name:        "search_prohibited_software",
		Description: "Search for commonly prohibited software (games, hacking tools, P2P, remote access). Returns a list of found prohibited software that should likely be removed.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"category": map[string]interface{}{
					"type":        "string",
					"description": "Category to search: 'games', 'hacking', 'p2p', 'remote', 'media', or 'all' (default: 'all')",
					"enum":        []string{"games", "hacking", "p2p", "remote", "media", "all"},
				},
			},
		},
		Handler:  toolSearchProhibitedSoftware,
		Mutating: false,
	})
}

func toolListInstalledSoftware(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Filter string `json:"filter"`
	}
	json.Unmarshal(args, &params)

	var cmd string
	if runtime.GOOS == "windows" {
		// Windows: Get installed programs from registry and Get-Package
		if params.Filter != "" {
			cmd = fmt.Sprintf(`
$filter = '%s'
$results = @()

# Get from Add/Remove Programs
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -like "*$filter*" } |
    ForEach-Object { $results += $_.DisplayName }
}

# Get Windows Store apps
Get-AppxPackage -ErrorAction SilentlyContinue | 
Where-Object { $_.Name -like "*$filter*" } |
ForEach-Object { $results += "Store: $($_.Name)" }

$results | Sort-Object -Unique
`, params.Filter)
		} else {
			cmd = `
$results = @()

# Get from Add/Remove Programs  
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName } |
    ForEach-Object { $results += $_.DisplayName }
}

# Get Windows Store apps (limited to first 50)
Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object -First 50 |
ForEach-Object { $results += "Store: $($_.Name)" }

$results | Sort-Object -Unique | Select-Object -First 200
`
		}
		output, err := RunCommand(ctx, cmd, false)
		if err != nil {
			return "", fmt.Errorf("failed to list software: %w", err)
		}
		return "=== Installed Software (Windows) ===\n" + output, nil
	} else {
		// Linux: Use dpkg, rpm, or pacman
		if params.Filter != "" {
			cmd = fmt.Sprintf(`
echo "=== Installed Packages (filtered by '%s') ==="
if command -v dpkg &>/dev/null; then
    dpkg -l 2>/dev/null | grep -i '%s' | awk '{print $2 " - " $3}' | head -100
elif command -v rpm &>/dev/null; then
    rpm -qa 2>/dev/null | grep -i '%s' | head -100
elif command -v pacman &>/dev/null; then
    pacman -Q 2>/dev/null | grep -i '%s' | head -100
fi

echo ""
echo "=== Snap Packages ==="
snap list 2>/dev/null | grep -i '%s' || echo "No snap packages or snap not installed"

echo ""
echo "=== Flatpak Apps ==="
flatpak list 2>/dev/null | grep -i '%s' || echo "No flatpak apps or flatpak not installed"
`, params.Filter, params.Filter, params.Filter, params.Filter, params.Filter, params.Filter)
		} else {
			cmd = `
echo "=== Installed Packages (first 150) ==="
if command -v dpkg &>/dev/null; then
    dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2}' | head -150
elif command -v rpm &>/dev/null; then
    rpm -qa 2>/dev/null | head -150
elif command -v pacman &>/dev/null; then
    pacman -Q 2>/dev/null | head -150
fi

echo ""
echo "=== Snap Packages ==="
snap list 2>/dev/null || echo "Snap not installed"

echo ""
echo "=== Flatpak Apps ==="
flatpak list 2>/dev/null || echo "Flatpak not installed"
`
		}
		output, err := RunCommand(ctx, cmd, false)
		if err != nil {
			return "", fmt.Errorf("failed to list software: %w", err)
		}
		return output, nil
	}
}

func toolRemoveSoftware(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		PackageName string `json:"package_name"`
		Purge       *bool  `json:"purge"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	purge := true
	if params.Purge != nil {
		purge = *params.Purge
	}

	var cmd string
	if runtime.GOOS == "windows" {
		// Windows: Try multiple removal methods
		cmd = fmt.Sprintf(`
$pkg = '%s'
$removed = $false

# Try WMI uninstall
$app = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$pkg*" }
if ($app) {
    $app.Uninstall() | Out-Null
    Write-Host "Removed via WMI: $($app.Name)"
    $removed = $true
}

# Try Appx removal (Store apps)
$appx = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$pkg*" }
if ($appx) {
    $appx | Remove-AppxPackage -ErrorAction SilentlyContinue
    Write-Host "Removed Store app: $($appx.Name)"
    $removed = $true
}

# Try winget
if (Get-Command winget -ErrorAction SilentlyContinue) {
    $wingetResult = winget uninstall --silent --accept-source-agreements "$pkg" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Removed via winget: $pkg"
        $removed = $true
    }
}

# Try chocolatey
if (Get-Command choco -ErrorAction SilentlyContinue) {
    choco uninstall "$pkg" -y --force 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Removed via chocolatey: $pkg"
        $removed = $true
    }
}

if (-not $removed) {
    Write-Host "Could not find or remove: $pkg"
    Write-Host "Try checking exact name with list_installed_software"
}
`, params.PackageName)
	} else {
		// Linux: Use appropriate package manager
		purgeFlag := ""
		if purge {
			purgeFlag = "--purge"
		}
		cmd = fmt.Sprintf(`
pkg='%s'
removed=false

# Try apt (Debian/Ubuntu)
if command -v apt-get &>/dev/null; then
    if dpkg -l | grep -q "^ii.*$pkg"; then
        apt-get remove %s -y "$pkg" 2>&1
        removed=true
    fi
fi

# Try dnf (Fedora/RHEL)
if command -v dnf &>/dev/null && [ "$removed" = "false" ]; then
    if rpm -q "$pkg" &>/dev/null; then
        dnf remove -y "$pkg" 2>&1
        removed=true
    fi
fi

# Try yum (older RHEL/CentOS)
if command -v yum &>/dev/null && [ "$removed" = "false" ]; then
    if rpm -q "$pkg" &>/dev/null; then
        yum remove -y "$pkg" 2>&1
        removed=true
    fi
fi

# Try pacman (Arch)
if command -v pacman &>/dev/null && [ "$removed" = "false" ]; then
    if pacman -Q "$pkg" &>/dev/null; then
        pacman -R --noconfirm "$pkg" 2>&1
        removed=true
    fi
fi

# Try snap
if command -v snap &>/dev/null; then
    if snap list 2>/dev/null | grep -q "$pkg"; then
        snap remove "$pkg" 2>&1
        removed=true
    fi
fi

# Try flatpak
if command -v flatpak &>/dev/null; then
    if flatpak list 2>/dev/null | grep -qi "$pkg"; then
        flatpak uninstall -y "$pkg" 2>&1
        removed=true
    fi
fi

if [ "$removed" = "false" ]; then
    echo "Package '$pkg' not found or could not be removed"
    echo "Try checking exact name with list_installed_software"
fi
`, params.PackageName, purgeFlag)
	}

	output, err := RunCommand(ctx, cmd, false)
	if err != nil {
		return "", fmt.Errorf("failed to remove software: %w", err)
	}
	return output, nil
}

func toolSearchProhibitedSoftware(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Category string `json:"category"`
	}
	json.Unmarshal(args, &params)

	if params.Category == "" {
		params.Category = "all"
	}

	// Define prohibited software patterns by category
	categories := map[string][]string{
		"games": {
			// Linux games
			"aisleriot", "gnome-mines", "gnome-sudoku", "gnome-mahjongg", "gnome-chess",
			"five-or-more", "four-in-a-row", "gnome-klotski", "gnome-nibbles", "gnome-robots",
			"gnome-tetravex", "quadrapassel", "swell-foop", "tali", "iagno", "lightsoff",
			"gnome-2048", "gnome-taquin", "supertuxkart", "0ad", "minetest", "freeciv",
			"frozen-bubble", "pingus", "tuxpaint", "kpat", "kmines", "kmahjongg",
			// Windows games
			"solitaire", "minesweeper", "chess", "hearts", "freecell", "mahjong",
			"tictactoe", "xbox", "minecraft", "steam",
		},
		"hacking": {
			"nmap", "zenmap", "wireshark", "tshark", "tcpdump", "ettercap", "bettercap",
			"netcat", "ncat", "nc", "masscan", "angry-ip-scanner",
			"john", "johntheripper", "hashcat", "ophcrack", "hydra", "medusa", "cain",
			"metasploit", "armitage", "beef", "sqlmap", "nikto", "burpsuite", "burp",
			"aircrack-ng", "kismet", "reaver", "wifite", "fern-wifi",
			"nessus", "openvas", "maltego", "setoolkit",
		},
		"p2p": {
			"transmission", "deluge", "qbittorrent", "utorrent", "vuze", "bittorrent",
			"rtorrent", "amule", "emule", "gnutella", "limewire", "frostwire", "kazaa",
			"bearshare", "ktorrent", "aria2",
		},
		"remote": {
			"tigervnc", "tightvnc", "x11vnc", "realvnc", "ultravnc", "vino",
			"teamviewer", "anydesk", "logmein", "rustdesk", "remmina",
			"cryptcat", "socat",
		},
		"media": {
			"plex", "emby", "jellyfin", "kodi", "ps3mediaserver", "minidlna",
			"universal-media-server", "vlc-server", "subsonic",
		},
	}

	var searchPatterns []string
	if params.Category == "all" {
		for _, patterns := range categories {
			searchPatterns = append(searchPatterns, patterns...)
		}
	} else {
		if patterns, ok := categories[params.Category]; ok {
			searchPatterns = patterns
		} else {
			return "", fmt.Errorf("unknown category: %s (use: games, hacking, p2p, remote, media, all)", params.Category)
		}
	}

	var cmd string
	if runtime.GOOS == "windows" {
		patternsJoined := strings.Join(searchPatterns, "|")
		cmd = fmt.Sprintf(`
$patterns = '%s' -split '\|'
$found = @()

# Search installed programs
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($pattern in $patterns) {
            if ($_.DisplayName -like "*$pattern*") {
                $found += "INSTALLED: $($_.DisplayName)"
                break
            }
        }
    }
}

# Search Store apps
Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object {
    foreach ($pattern in $patterns) {
        if ($_.Name -like "*$pattern*") {
            $found += "STORE APP: $($_.Name)"
            break
        }
    }
}

if ($found.Count -eq 0) {
    Write-Host "No prohibited software found in category: %s"
} else {
    Write-Host "=== PROHIBITED SOFTWARE FOUND ==="
    $found | Sort-Object -Unique
    Write-Host ""
    Write-Host "Use remove_software to uninstall these items"
}
`, patternsJoined, params.Category)
	} else {
		// Build grep pattern
		grepPattern := strings.Join(searchPatterns, "\\|")
		cmd = fmt.Sprintf(`
echo "=== Searching for prohibited software (category: %s) ==="
echo ""

found=0

# Search dpkg
if command -v dpkg &>/dev/null; then
    echo "--- Installed packages (apt/dpkg) ---"
    matches=$(dpkg -l 2>/dev/null | grep -iE '%s' | awk '{print "INSTALLED: " $2}')
    if [ -n "$matches" ]; then
        echo "$matches"
        found=1
    fi
fi

# Search rpm
if command -v rpm &>/dev/null; then
    echo "--- Installed packages (rpm) ---"
    matches=$(rpm -qa 2>/dev/null | grep -iE '%s')
    if [ -n "$matches" ]; then
        echo "$matches" | sed 's/^/INSTALLED: /'
        found=1
    fi
fi

# Search snap
if command -v snap &>/dev/null; then
    echo "--- Snap packages ---"
    matches=$(snap list 2>/dev/null | grep -iE '%s' | awk '{print "SNAP: " $1}')
    if [ -n "$matches" ]; then
        echo "$matches"
        found=1
    fi
fi

# Search flatpak
if command -v flatpak &>/dev/null; then
    echo "--- Flatpak apps ---"
    matches=$(flatpak list 2>/dev/null | grep -iE '%s' | awk '{print "FLATPAK: " $1}')
    if [ -n "$matches" ]; then
        echo "$matches"
        found=1
    fi
fi

if [ "$found" -eq 0 ]; then
    echo "No prohibited software found in category: %s"
else
    echo ""
    echo "Use remove_software to uninstall these items"
fi
`, params.Category, grepPattern, grepPattern, grepPattern, grepPattern, params.Category)
	}

	output, err := RunCommand(ctx, cmd, false)
	if err != nil {
		return "", fmt.Errorf("search failed: %w", err)
	}
	return output, nil
}

