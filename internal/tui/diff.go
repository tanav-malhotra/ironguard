package tui

import (
	"fmt"
	"strings"
)

// DiffLine represents a line in a diff view.
type DiffLine struct {
	Type    DiffLineType
	Content string
	LineNum int
}

// DiffLineType indicates the type of diff line.
type DiffLineType int

const (
	DiffLineContext DiffLineType = iota
	DiffLineAdd
	DiffLineRemove
	DiffLineHeader
)

// GenerateDiff creates a simple unified diff between two strings.
func GenerateDiff(oldContent, newContent, filename string) []DiffLine {
	var result []DiffLine
	
	// Add header
	result = append(result, DiffLine{Type: DiffLineHeader, Content: "--- " + filename + " (before)"})
	result = append(result, DiffLine{Type: DiffLineHeader, Content: "+++ " + filename + " (after)"})
	
	oldLines := strings.Split(oldContent, "\n")
	newLines := strings.Split(newContent, "\n")
	
	// Simple line-by-line diff (not optimal but good enough for display)
	// Use LCS-based approach for better diffs
	lcs := computeLCS(oldLines, newLines)
	
	oldIdx, newIdx := 0, 0
	for _, match := range lcs {
		// Add removed lines (from old that aren't in LCS)
		for oldIdx < match.oldIdx {
			result = append(result, DiffLine{
				Type:    DiffLineRemove,
				Content: oldLines[oldIdx],
				LineNum: oldIdx + 1,
			})
			oldIdx++
		}
		
		// Add added lines (from new that aren't in LCS)
		for newIdx < match.newIdx {
			result = append(result, DiffLine{
				Type:    DiffLineAdd,
				Content: newLines[newIdx],
				LineNum: newIdx + 1,
			})
			newIdx++
		}
		
		// Add context line (matching)
		if oldIdx < len(oldLines) {
			result = append(result, DiffLine{
				Type:    DiffLineContext,
				Content: oldLines[oldIdx],
				LineNum: oldIdx + 1,
			})
		}
		oldIdx++
		newIdx++
	}
	
	// Handle remaining lines
	for oldIdx < len(oldLines) {
		result = append(result, DiffLine{
			Type:    DiffLineRemove,
			Content: oldLines[oldIdx],
			LineNum: oldIdx + 1,
		})
		oldIdx++
	}
	
	for newIdx < len(newLines) {
		result = append(result, DiffLine{
			Type:    DiffLineAdd,
			Content: newLines[newIdx],
			LineNum: newIdx + 1,
		})
		newIdx++
	}
	
	return result
}

// lcsMatch represents a match in the LCS.
type lcsMatch struct {
	oldIdx int
	newIdx int
}

// computeLCS computes the longest common subsequence of lines.
func computeLCS(old, new []string) []lcsMatch {
	m, n := len(old), len(new)
	if m == 0 || n == 0 {
		return nil
	}
	
	// Build LCS table
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if old[i-1] == new[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				dp[i][j] = max(dp[i-1][j], dp[i][j-1])
			}
		}
	}
	
	// Backtrack to find matches
	var matches []lcsMatch
	i, j := m, n
	for i > 0 && j > 0 {
		if old[i-1] == new[j-1] {
			matches = append([]lcsMatch{{oldIdx: i - 1, newIdx: j - 1}}, matches...)
			i--
			j--
		} else if dp[i-1][j] > dp[i][j-1] {
			i--
		} else {
			j--
		}
	}
	
	return matches
}

// FormatDiff renders a diff with styling.
func (s Styles) FormatDiff(diff []DiffLine, maxLines int) string {
	var sb strings.Builder
	
	shown := 0
	for _, line := range diff {
		if maxLines > 0 && shown >= maxLines {
			sb.WriteString(s.Muted.Render(fmt.Sprintf("... (%d more lines)", len(diff)-shown)))
			break
		}
		
		switch line.Type {
		case DiffLineHeader:
			sb.WriteString(s.DiffHeader.Render(line.Content))
		case DiffLineAdd:
			sb.WriteString(s.DiffAdd.Render("+ " + line.Content))
		case DiffLineRemove:
			sb.WriteString(s.DiffRemove.Render("- " + line.Content))
		case DiffLineContext:
			sb.WriteString(s.Muted.Render("  " + line.Content))
		}
		sb.WriteString("\n")
		shown++
	}
	
	return sb.String()
}

// RenderProgressBar creates a text-based progress bar.
func (s Styles) RenderProgressBar(current, total int, width int) string {
	if total <= 0 {
		return s.Muted.Render("[" + strings.Repeat("░", width) + "]")
	}
	
	percent := float64(current) / float64(total)
	filled := int(percent * float64(width))
	if filled > width {
		filled = width
	}
	
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	percentStr := fmt.Sprintf("%3.0f%%", percent*100)
	
	return s.ProgressFilled.Render("["+bar[:filled]) + 
		s.ProgressEmpty.Render(bar[filled:]+"]") + " " + 
		s.Value.Render(percentStr)
}

// RenderSpinner returns a spinner character based on frame.
func RenderSpinner(frame int) string {
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	return spinners[frame%len(spinners)]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

