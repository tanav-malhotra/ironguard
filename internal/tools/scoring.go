package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// ScoreReport represents a parsed CyberPatriot scoring report.
type ScoreReport struct {
	TotalScore    int      `json:"total_score"`
	MaxScore      int      `json:"max_score"`
	Percentage    float64  `json:"percentage"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Penalties     []string `json:"penalties"`
	RawContent    string   `json:"raw_content"`
}

// Vulnerability represents a single vulnerability item.
type Vulnerability struct {
	Description string `json:"description"`
	Points      int    `json:"points"`
	Found       bool   `json:"found"`
}

// RegisterScoringTools adds scoring-related tools to the registry.
func (r *Registry) RegisterScoringTools() {
	// Read scoring report
	r.Register(&Tool{
		Name:        "read_score_report",
		Description: "Read and parse the CyberPatriot scoring report to see current score, found vulnerabilities, and remaining issues",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolReadScoreReport,
		Mutating: false,
	})

	// Get current score
	r.Register(&Tool{
		Name:        "get_current_score",
		Description: "Get just the current score (quick check without full report parsing)",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolGetCurrentScore,
		Mutating: false,
	})

	// Watch score changes
	r.Register(&Tool{
		Name:        "check_score_improved",
		Description: "Check if the score has changed since the last check (useful after making changes)",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"previous_score": map[string]interface{}{
					"type":        "integer",
					"description": "The previous score to compare against",
				},
			},
			"required": []string{"previous_score"},
		},
		Handler:  toolCheckScoreImproved,
		Mutating: false,
	})
}

func toolReadScoreReport(ctx context.Context, args json.RawMessage) (string, error) {
	report, err := readScoreReport()
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== CYBERPATRIOT SCORE REPORT ===\n\n"))
	sb.WriteString(fmt.Sprintf("Current Score: %d / %d (%.1f%%)\n\n", report.TotalScore, report.MaxScore, report.Percentage))

	if len(report.Vulnerabilities) > 0 {
		sb.WriteString("FOUND VULNERABILITIES:\n")
		for _, v := range report.Vulnerabilities {
			if v.Found {
				sb.WriteString(fmt.Sprintf("  ✓ %s (+%d pts)\n", v.Description, v.Points))
			}
		}
		sb.WriteString("\n")
	}

	// Count remaining
	remaining := 0
	for _, v := range report.Vulnerabilities {
		if !v.Found {
			remaining++
		}
	}
	if remaining > 0 {
		sb.WriteString(fmt.Sprintf("REMAINING: %d vulnerabilities still to find\n", remaining))
	}

	if len(report.Penalties) > 0 {
		sb.WriteString("\nPENALTIES:\n")
		for _, p := range report.Penalties {
			sb.WriteString(fmt.Sprintf("  ✗ %s\n", p))
		}
	}

	if report.TotalScore >= report.MaxScore {
		sb.WriteString("\n🎉 PERFECT SCORE! All vulnerabilities found!\n")
	}

	return sb.String(), nil
}

func toolGetCurrentScore(ctx context.Context, args json.RawMessage) (string, error) {
	report, err := readScoreReport()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("Current Score: %d / %d (%.1f%%)", report.TotalScore, report.MaxScore, report.Percentage), nil
}

func toolCheckScoreImproved(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		PreviousScore int `json:"previous_score"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	report, err := readScoreReport()
	if err != nil {
		return "", err
	}

	diff := report.TotalScore - params.PreviousScore
	if diff > 0 {
		return fmt.Sprintf("✓ Score IMPROVED! +%d points (now %d/%d)", diff, report.TotalScore, report.MaxScore), nil
	} else if diff < 0 {
		return fmt.Sprintf("✗ Score DECREASED! %d points (now %d/%d) - check for penalties", diff, report.TotalScore, report.MaxScore), nil
	}
	return fmt.Sprintf("Score unchanged at %d/%d", report.TotalScore, report.MaxScore), nil
}

func readScoreReport() (*ScoreReport, error) {
	// Find the scoring report file
	reportPath, err := findScoreReport()
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read score report: %w", err)
	}

	return parseScoreReport(string(content))
}

func findScoreReport() (string, error) {
	var searchPaths []string

	if runtime.GOOS == "windows" {
		// Common Windows locations for CyberPatriot scoring report
		// Check exact official names first, then fallback to globs for practice images
		desktopPath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
		searchPaths = []string{
			// Exact official name with extension
			filepath.Join(desktopPath, "CyberPatriot Scoring Report.html"),
			filepath.Join(desktopPath, "CyberPatriot Scoring Report.htm"),
			// Without extension (edge case)
			filepath.Join(desktopPath, "CyberPatriot Scoring Report"),
			// Standard CyberPatriot install locations
			`C:\CyberPatriot\Scoring Report.html`,
			`C:\CyberPatriot\ScoringReport.html`,
			// Generic names
			filepath.Join(desktopPath, "Scoring Report.html"),
			filepath.Join(desktopPath, "ScoringReport.html"),
			// Public desktop
			filepath.Join(os.Getenv("PUBLIC"), "Desktop", "CyberPatriot Scoring Report.html"),
			filepath.Join(os.Getenv("PUBLIC"), "Desktop", "Scoring Report.html"),
		}

		// Glob fallback for variations and third-party practice images
		matches, _ := filepath.Glob(filepath.Join(desktopPath, "*[Ss]cor*[Rr]eport*"))
		searchPaths = append(searchPaths, matches...)

		// Check Program Files
		programFiles := []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")}
		for _, pf := range programFiles {
			if pf != "" {
				searchPaths = append(searchPaths,
					filepath.Join(pf, "CyberPatriot", "Scoring Report.html"),
					filepath.Join(pf, "CyberPatriot", "ScoringReport.html"),
				)
			}
		}
	} else {
		// Linux locations
		// Check exact official names first, then fallback to globs for practice images
		home := os.Getenv("HOME")
		desktopPath := filepath.Join(home, "Desktop")
		searchPaths = []string{
			// Exact official name with extension
			filepath.Join(desktopPath, "CyberPatriot Scoring Report.html"),
			filepath.Join(desktopPath, "CyberPatriot Scoring Report.htm"),
			// Without extension (edge case)
			filepath.Join(desktopPath, "CyberPatriot Scoring Report"),
			// Standard CyberPatriot install locations
			"/opt/CyberPatriot/Scoring Report.html",
			"/opt/CyberPatriot/ScoringReport.html",
			// Generic names
			filepath.Join(desktopPath, "Scoring Report.html"),
			filepath.Join(desktopPath, "ScoringReport.html"),
			"/home/CyberPatriot/Scoring Report.html",
		}

		// Glob fallback for variations and third-party practice images
		matches, _ := filepath.Glob(filepath.Join(desktopPath, "*[Ss]cor*[Rr]eport*"))
		searchPaths = append(searchPaths, matches...)
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("scoring report not found - looked in common CyberPatriot locations")
}

func parseScoreReport(content string) (*ScoreReport, error) {
	report := &ScoreReport{
		RawContent: content,
		MaxScore:   100, // Default assumption
	}

	// Try to extract score using common patterns
	// Pattern 1: "Score: XX / YY" or "Score: XX/YY"
	scoreRegex := regexp.MustCompile(`(?i)score[:\s]+(\d+)\s*/\s*(\d+)`)
	if matches := scoreRegex.FindStringSubmatch(content); len(matches) >= 3 {
		report.TotalScore, _ = strconv.Atoi(matches[1])
		report.MaxScore, _ = strconv.Atoi(matches[2])
	}

	// Pattern 2: Just a number followed by "points" or "pts"
	if report.TotalScore == 0 {
		pointsRegex := regexp.MustCompile(`(\d+)\s*(?:points?|pts)`)
		if matches := pointsRegex.FindStringSubmatch(content); len(matches) >= 2 {
			report.TotalScore, _ = strconv.Atoi(matches[1])
		}
	}

	// Pattern 3: Look for percentage
	percentRegex := regexp.MustCompile(`(\d+(?:\.\d+)?)\s*%`)
	if matches := percentRegex.FindStringSubmatch(content); len(matches) >= 2 {
		report.Percentage, _ = strconv.ParseFloat(matches[1], 64)
	} else if report.MaxScore > 0 {
		report.Percentage = float64(report.TotalScore) / float64(report.MaxScore) * 100
	}

	// Extract found vulnerabilities (lines with checkmarks or "found")
	foundRegex := regexp.MustCompile(`(?i)(?:✓|✔|found|secured?|fixed|enabled?|disabled?)[:\s]*(.+?)(?:\s*[-+]?\s*\d+\s*(?:pts?|points?))?(?:\n|$)`)
	for _, match := range foundRegex.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			desc := strings.TrimSpace(match[1])
			if desc != "" && len(desc) > 3 {
				report.Vulnerabilities = append(report.Vulnerabilities, Vulnerability{
					Description: desc,
					Found:       true,
				})
			}
		}
	}

	// Extract penalties
	penaltyRegex := regexp.MustCompile(`(?i)(?:penalty|✗|✘|lost)[:\s]*(.+?)(?:\s*[-]?\s*\d+\s*(?:pts?|points?))?(?:\n|$)`)
	for _, match := range penaltyRegex.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			desc := strings.TrimSpace(match[1])
			if desc != "" && len(desc) > 3 {
				report.Penalties = append(report.Penalties, desc)
			}
		}
	}

	return report, nil
}

