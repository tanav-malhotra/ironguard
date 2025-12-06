package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// MentionType represents the type of @ mention.
type MentionType int

const (
	MentionFile MentionType = iota
	MentionURL
)

// Mention represents an @ mention in user input.
type Mention struct {
	Type      MentionType
	Original  string // Original text (e.g., "@README.html")
	Path      string // Resolved path or URL
	Content   string // File content (if loaded)
	Error     string // Error message if failed to load
	IsImage   bool   // True if this is an image file
	ImageData []byte // Raw image data for multi-modal
	MediaType string // MIME type for images
}

// ParseMentions extracts @ mentions from user input.
// Supports:
// - @filename.txt (files on Desktop or current dir)
// - @/absolute/path/to/file
// - @./relative/path
// - @https://example.com/page (URLs)
func ParseMentions(input string) (string, []Mention) {
	var mentions []Mention

	// Regex to match @ followed by a path or URL
	// Matches: @word, @path/to/file, @./relative, @/absolute, @https://...
	mentionRegex := regexp.MustCompile(`@((?:https?://[^\s]+)|(?:[^\s@]+))`)

	matches := mentionRegex.FindAllStringSubmatch(input, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		original := match[0] // Full match including @
		ref := match[1]      // The reference without @

		mention := Mention{
			Original: original,
		}

		// Check if it's a URL
		if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
			mention.Type = MentionURL
			mention.Path = ref
		} else {
			mention.Type = MentionFile
			mention.Path = resolveFilePath(ref)
		}

		mentions = append(mentions, mention)
	}

	return input, mentions
}

// isImageFile checks if a file is an image based on extension.
func isImageFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg":
		return true
	}
	return false
}

// isBinaryFile checks if a file is likely binary based on extension.
func isBinaryFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true,
		".pdf": true, ".doc": true, ".xls": true, ".ppt": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wav": true,
		".pcap": true, ".pcapng": true,
	}
	return binaryExts[ext]
}

// getMediaType returns the MIME type for an image file
func getMediaType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	default:
		return "image/png"
	}
}

// LoadMentionContent loads the content of file mentions.
func LoadMentionContent(mentions []Mention) []Mention {
	for i := range mentions {
		if mentions[i].Type == MentionFile {
			// Check if it's an image file - load as binary for multi-modal
			if isImageFile(mentions[i].Path) {
				data, err := os.ReadFile(mentions[i].Path)
				if err != nil {
					mentions[i].Error = err.Error()
				} else {
					mentions[i].IsImage = true
					mentions[i].ImageData = data
					mentions[i].MediaType = getMediaType(mentions[i].Path)
					mentions[i].Content = "[Image attached: " + filepath.Base(mentions[i].Path) + "]"
				}
				continue
			}
			
			// Check if it's a binary file
			if isBinaryFile(mentions[i].Path) {
				ext := strings.ToLower(filepath.Ext(mentions[i].Path))
				var hint string
				switch ext {
				case ".pdf":
					hint = "Use read_pdf tool to extract text from this file."
				case ".pcap", ".pcapng":
					hint = "Use analyze_pcap tool to analyze this capture file."
				default:
					hint = "This is a binary file and cannot be read as text."
				}
				mentions[i].Content = "[BINARY FILE: " + mentions[i].Path + "]\n" + hint
				continue
			}
			
			content, err := os.ReadFile(mentions[i].Path)
			if err != nil {
				mentions[i].Error = err.Error()
			} else {
				// Truncate very large files
				text := string(content)
				if len(text) > 50000 {
					text = text[:50000] + "\n\n... [truncated - file too large]"
				}
				mentions[i].Content = text
			}
		}
		// URL mentions are handled by the fetch_url tool
	}
	return mentions
}

// resolveFilePath tries to find the file in common locations.
func resolveFilePath(ref string) string {
	// If it's already an absolute path, return it
	if filepath.IsAbs(ref) {
		return ref
	}

	// If it starts with ./ or ../, treat as relative to current dir
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") {
		abs, err := filepath.Abs(ref)
		if err == nil {
			return abs
		}
		return ref
	}

	// Try common locations
	searchPaths := []string{
		// Current directory
		ref,
		// Desktop
		filepath.Join(getDesktopPath(), ref),
		// Home directory
		filepath.Join(getHomePath(), ref),
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			abs, err := filepath.Abs(path)
			if err == nil {
				return abs
			}
			return path
		}
	}

	// Return the original ref if not found (will error when loading)
	return ref
}

// getDesktopPath returns the user's Desktop path.
func getDesktopPath() string {
	home := getHomePath()
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "Desktop")
	}
	// Linux - try common locations
	desktop := filepath.Join(home, "Desktop")
	if _, err := os.Stat(desktop); err == nil {
		return desktop
	}
	return filepath.Join(home, "desktop")
}

// getHomePath returns the user's home directory.
func getHomePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return home
}

// ExpandMentionsInMessage expands @ mentions in a message, replacing them with file contents.
func ExpandMentionsInMessage(input string) (string, []Mention) {
	_, mentions := ParseMentions(input)
	mentions = LoadMentionContent(mentions)

	// Build the expanded message
	expanded := input

	// Add file contents as context
	var fileContext strings.Builder
	for _, m := range mentions {
		if m.Type == MentionFile {
			if m.Error != "" {
				fileContext.WriteString("\n\n--- Error loading " + m.Original + " ---\n")
				fileContext.WriteString(m.Error)
			} else if m.Content != "" {
				fileContext.WriteString("\n\n--- Contents of " + m.Original + " (" + m.Path + ") ---\n")
				fileContext.WriteString(m.Content)
				fileContext.WriteString("\n--- End of " + m.Original + " ---")
			}
		}
	}

	if fileContext.Len() > 0 {
		expanded = input + "\n" + fileContext.String()
	}

	return expanded, mentions
}

// GetFileCompletions returns file completions for a partial path.
func GetFileCompletions(partial string, maxResults int) []string {
	var completions []string

	// Get the directory and prefix
	dir := filepath.Dir(partial)
	prefix := filepath.Base(partial)

	// If partial is just a name (no path separator), search Desktop first
	if !strings.Contains(partial, string(filepath.Separator)) && !strings.Contains(partial, "/") {
		desktop := getDesktopPath()
		completions = append(completions, getMatchingFiles(desktop, partial, maxResults/2)...)
	}

	// Search the specified directory
	if dir != "." {
		completions = append(completions, getMatchingFiles(dir, prefix, maxResults/2)...)
	}

	// Limit results
	if len(completions) > maxResults {
		completions = completions[:maxResults]
	}

	return completions
}

// getMatchingFiles returns files in a directory matching a prefix.
func getMatchingFiles(dir, prefix string, maxResults int) []string {
	var matches []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return matches
	}

	prefix = strings.ToLower(prefix)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(strings.ToLower(name), prefix) {
			fullPath := filepath.Join(dir, name)
			matches = append(matches, fullPath)
			if len(matches) >= maxResults {
				break
			}
		}
	}

	return matches
}

// FormatMentionForDisplay formats a mention for display in the TUI.
func FormatMentionForDisplay(m Mention) string {
	switch m.Type {
	case MentionFile:
		if m.Error != "" {
			return "📄 " + m.Original + " (error: " + m.Error + ")"
		}
		return "📄 " + m.Original + " → " + m.Path
	case MentionURL:
		return "🔗 " + m.Original
	default:
		return m.Original
	}
}

