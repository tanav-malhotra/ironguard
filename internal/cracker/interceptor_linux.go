//go:build linux

package cracker

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// startLinuxInterception starts strace-based interception on Linux
func (c *Cracker) startLinuxInterception(ctx context.Context, pid int) error {
	// Check if we have root/sudo access
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required for strace interception (run with sudo)")
	}

	// Build strace command
	// -p PID: attach to process
	// -f: follow forks
	// -e trace=open,openat,read,stat,access: trace file operations
	// -e read=3,4,5,6: show data read from file descriptors (to see values)
	args := []string{
		"-p", fmt.Sprintf("%d", pid),
		"-f",
		"-e", "trace=open,openat,read,stat,access",
		"-s", "256", // Show up to 256 bytes of strings
	}

	cmd := exec.CommandContext(ctx, "strace", args...)
	
	// strace outputs to stderr
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get strace stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start strace: %w", err)
	}

	// Parse strace output in a goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		// Increase buffer size for long lines
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			c.parseStraceLine(line)
		}

		// Wait for strace to finish
		cmd.Wait()
		
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	return nil
}

// Regex patterns for parsing strace output
var (
	// Match: openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 4
	// Captures: path, fd
	openatPatternFull = regexp.MustCompile(`openat\(AT_FDCWD,\s*"([^"]+)"[^)]*\)\s*=\s*(\d+)`)
	openatPattern = regexp.MustCompile(`openat\(AT_FDCWD,\s*"([^"]+)"`)
	
	// Match: open("/etc/passwd", O_RDONLY) = 4
	// Captures: path, fd
	openPatternFull = regexp.MustCompile(`open\("([^"]+)"[^)]*\)\s*=\s*(\d+)`)
	openPattern = regexp.MustCompile(`open\("([^"]+)"`)
	
	// Match: stat("/etc/passwd", {st_mode=...}) = 0
	statPattern = regexp.MustCompile(`stat\("([^"]+)"`)
	
	// Match: access("/etc/passwd", ...) = 0
	accessPattern = regexp.MustCompile(`access\("([^"]+)"`)
	
	// Match: read(4, "root:x:0:0:root...", 4096) = 3604
	// Captures: fd, content
	readPatternFull = regexp.MustCompile(`read\((\d+),\s*"([^"]*)"`)
	readPattern = regexp.MustCompile(`read\(\d+,\s*"([^"]*)"`)
	
	// Match: close(4) = 0
	// Captures: fd
	closePattern = regexp.MustCompile(`close\((\d+)\)\s*=\s*0`)
	
	// Match process cmdline reads: /proc/1234/cmdline
	procCmdlinePattern = regexp.MustCompile(`/proc/(\d+)/cmdline`)
)

// fdTracker tracks file descriptor to path mappings
type fdTracker struct {
	mu    sync.RWMutex
	fdMap map[int]string // fd -> file path
}

func newFDTracker() *fdTracker {
	return &fdTracker{
		fdMap: make(map[int]string),
	}
}

func (t *fdTracker) Set(fd int, path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fdMap[fd] = path
}

func (t *fdTracker) Get(fd int) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	path, ok := t.fdMap[fd]
	return path, ok
}

func (t *fdTracker) Delete(fd int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fdMap, fd)
}

// Global FD tracker for the strace parser
var globalFDTracker = newFDTracker()

// Files to ignore (noise)
var ignoredPaths = map[string]bool{
	"/etc/ld.so.cache":      true,
	"/etc/localtime":        true,
	"/etc/nsswitch.conf":    true,
	"/etc/host.conf":        true,
	"/etc/resolv.conf":      true,
	"/etc/gai.conf":         true,
	"/usr/lib":              true,
	"/lib":                  true,
	"/proc/self":            true,
	"/sys/devices/system":   true,
}

// parseStraceLine parses a single line of strace output
func (c *Cracker) parseStraceLine(line string) {
	// Skip lines that indicate errors
	if strings.Contains(line, "ENOENT") || strings.Contains(line, "= -1") {
		return
	}

	// Handle close() - remove FD mapping
	if matches := closePattern.FindStringSubmatch(line); len(matches) > 1 {
		if fd, err := strconv.Atoi(matches[1]); err == nil {
			globalFDTracker.Delete(fd)
		}
		return
	}

	// Handle read() - attribute content to file via FD mapping
	if matches := readPatternFull.FindStringSubmatch(line); len(matches) > 2 {
		if fd, err := strconv.Atoi(matches[1]); err == nil {
			content := matches[2]
			if path, ok := globalFDTracker.Get(fd); ok && content != "" {
				// We have a read from a known file - enhance the finding
				c.handleReadContent(path, content)
			}
		}
		return
	}

	// Try to extract file path and track FD
	var path string
	var fd int = -1
	var findingType FindingType

	// Check for openat with FD result
	if matches := openatPatternFull.FindStringSubmatch(line); len(matches) > 2 {
		path = matches[1]
		if fdNum, err := strconv.Atoi(matches[2]); err == nil {
			fd = fdNum
		}
		findingType = FindingTypeFile
	} else if matches := openPatternFull.FindStringSubmatch(line); len(matches) > 2 {
		path = matches[1]
		if fdNum, err := strconv.Atoi(matches[2]); err == nil {
			fd = fdNum
		}
		findingType = FindingTypeFile
	} else if matches := openatPattern.FindStringSubmatch(line); len(matches) > 1 {
		path = matches[1]
		findingType = FindingTypeFile
	} else if matches := openPattern.FindStringSubmatch(line); len(matches) > 1 {
		path = matches[1]
		findingType = FindingTypeFile
	} else if matches := statPattern.FindStringSubmatch(line); len(matches) > 1 {
		path = matches[1]
		findingType = FindingTypeFile
	} else if matches := accessPattern.FindStringSubmatch(line); len(matches) > 1 {
		path = matches[1]
		findingType = FindingTypeFile
	}

	// Skip if no path found
	if path == "" {
		return
	}

	// Track FD → path mapping
	if fd >= 0 {
		globalFDTracker.Set(fd, path)
	}

	// Skip ignored paths
	for ignored := range ignoredPaths {
		if strings.HasPrefix(path, ignored) {
			return
		}
	}

	// Skip library files
	if strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
		return
	}

	// Check for special paths
	if strings.HasPrefix(path, "/proc/sys/") {
		findingType = FindingTypeKernelParam
	} else if strings.Contains(path, "Forensics") {
		findingType = FindingTypeForensics
	} else if matches := procCmdlinePattern.FindStringSubmatch(path); len(matches) > 1 {
		// This is a process check - extract PID and look up what process it is
		c.handleProcessCheck(matches[1])
		return
	}

	// Get current value and generate hints
	currentVal, expectedVal, hint := c.analyzeFile(path, findingType)

	finding := Finding{
		Type:        findingType,
		Path:        path,
		CurrentVal:  currentVal,
		ExpectedVal: expectedVal,
		FixHint:     hint,
	}

	c.addFinding(finding)
}

// handleReadContent processes content read from a file and enhances findings
func (c *Cracker) handleReadContent(path, content string) {
	// Skip noise paths
	for ignored := range ignoredPaths {
		if strings.HasPrefix(path, ignored) {
			return
		}
	}

	// Skip library files
	if strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
		return
	}

	// This provides additional context about what the scoring engine actually read
	// Try to enhance an existing finding with the read content
	c.mu.Lock()
	defer c.mu.Unlock()

	// Look for an existing finding for this path
	for i := range c.findings {
		if c.findings[i].Path == path && c.findings[i].ReadContent == "" {
			// Store the first 200 chars of content for context
			if len(content) > 200 {
				content = content[:200] + "..."
			}
			c.findings[i].ReadContent = content
			return
		}
	}
}

// handleProcessCheck handles when the scoring engine reads a process cmdline
func (c *Cracker) handleProcessCheck(pidStr string) {
	// Read the process cmdline to see what it is
	cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", pidStr)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return
	}

	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	if cmdline == "" {
		return
	}

	// Check if this looks like a suspicious process
	suspicious, reason := isSuspiciousProcess(cmdline)
	
	finding := Finding{
		Type:       FindingTypeProcess,
		Path:       cmdline,
		CurrentVal: "RUNNING",
	}

	if suspicious {
		finding.ExpectedVal = "STOPPED/REMOVED"
		finding.FixHint = reason
	} else {
		// Just informational - scoring engine is checking this service
		finding.FixHint = "Scoring engine is monitoring this service"
	}

	c.addFinding(finding)
}

// isSuspiciousProcess checks if a process looks malicious
func isSuspiciousProcess(cmdline string) (bool, string) {
	cmdlineLower := strings.ToLower(cmdline)

	// Known backdoor patterns
	suspiciousPatterns := []struct {
		pattern string
		reason  string
	}{
		{"backdoor", "Potential backdoor detected"},
		{"kneelb4zod", "Known CyberPatriot backdoor (Superman theme)"},
		{"nc -l", "Netcat listener (potential backdoor)"},
		{"ncat -l", "Ncat listener (potential backdoor)"},
		{"netcat", "Netcat (potential backdoor)"},
		{"/dev/tcp/", "Bash TCP backdoor"},
		{"reverse", "Potential reverse shell"},
		{"bind shell", "Potential bind shell"},
		{"cryptominer", "Cryptominer detected"},
		{"xmrig", "XMRig cryptominer detected"},
		{"coinhive", "Coinhive miner detected"},
		{".hidden", "Hidden file execution"},
		{"/tmp/.", "Suspicious temp file execution"},
	}

	for _, p := range suspiciousPatterns {
		if strings.Contains(cmdlineLower, p.pattern) {
			return true, p.reason
		}
	}

	return false, ""
}

// analyzeFile reads current value and suggests fixes based on heuristics
func (c *Cracker) analyzeFile(path string, fType FindingType) (current, expected, hint string) {
	// Read current value
	data, err := os.ReadFile(path)
	if err != nil {
		current = "(unable to read)"
		return
	}

	content := string(data)

	// Apply heuristics based on file path
	switch {
	case path == "/etc/ufw/ufw.conf":
		if strings.Contains(content, "ENABLED=no") {
			current = "ENABLED=no"
			expected = "ENABLED=yes"
			hint = "Enable UFW: sudo ufw enable"
		} else if strings.Contains(content, "ENABLED=yes") {
			current = "ENABLED=yes"
			expected = "ENABLED=yes"
			hint = "Firewall is already enabled"
		}

	case path == "/proc/sys/kernel/randomize_va_space":
		content = strings.TrimSpace(content)
		current = content
		if content != "2" {
			expected = "2"
			hint = "Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space"
		} else {
			expected = "2"
			hint = "ASLR is enabled"
		}

	case path == "/proc/sys/net/ipv4/tcp_syncookies":
		content = strings.TrimSpace(content)
		current = content
		if content != "1" {
			expected = "1"
			hint = "Enable SYN cookies: echo 1 > /proc/sys/net/ipv4/tcp_syncookies"
		} else {
			expected = "1"
			hint = "SYN cookies enabled"
		}

	case path == "/etc/pam.d/common-auth":
		if strings.Contains(content, "nullok") {
			current = "nullok present"
			expected = "nullok removed"
			hint = "Remove 'nullok' from PAM config to prevent blank passwords"
		} else {
			current = "nullok not present"
			hint = "Blank passwords already prevented"
		}

	case path == "/etc/pam.d/common-password":
		if !strings.Contains(content, "minlen") {
			current = "no password complexity"
			expected = "complexity enabled"
			hint = "Add password complexity: minlen=12 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1"
		} else {
			current = "complexity configured"
		}

	case path == "/etc/passwd":
		current = fmt.Sprintf("%d users", strings.Count(content, "\n"))
		hint = "Check for unauthorized users"

	case path == "/etc/shadow":
		current = "password hashes"
		hint = "Check for empty password fields (::)"

	case path == "/etc/group":
		current = "group memberships"
		hint = "Check sudo/admin group members"

	case strings.Contains(path, "Forensics"):
		if strings.Contains(content, "ANSWER:") && !strings.Contains(content, "<Type Answer Here>") {
			current = "ANSWERED"
			hint = "Forensics question appears to be answered"
		} else {
			current = "UNANSWERED"
			expected = "ANSWERED"
			hint = "This forensics question needs to be answered!"
		}

	case strings.HasPrefix(path, "/proc/sys/"):
		current = strings.TrimSpace(content)
		hint = "Kernel parameter - check if secure value"

	default:
		// Generic - just show first line
		lines := strings.SplitN(content, "\n", 2)
		if len(lines) > 0 && len(lines[0]) > 50 {
			current = lines[0][:50] + "..."
		} else if len(lines) > 0 {
			current = lines[0]
		}
	}

	return
}

