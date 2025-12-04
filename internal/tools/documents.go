package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// RegisterDocumentTools adds tools for reading binary document formats.
func (r *Registry) RegisterDocumentTools() {
	// PCAP analyzer
	r.Register(&Tool{
		Name:        "analyze_pcap",
		Description: "Analyze a PCAP (packet capture) file and extract useful information like protocols, IPs, ports, and potential passwords/credentials. Useful for forensics questions involving network captures.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the .pcap or .pcapng file",
				},
			},
			"required": []string{"path"},
		},
		Handler:  toolAnalyzePcap,
		Mutating: false,
	})

	// PDF reader
	r.Register(&Tool{
		Name:        "read_pdf",
		Description: "Extract text content from a PDF file. Useful for reading documentation or forensics files in PDF format.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the PDF file",
				},
			},
			"required": []string{"path"},
		},
		Handler:  toolReadPDF,
		Mutating: false,
	})

	// DOCX reader
	r.Register(&Tool{
		Name:        "read_docx",
		Description: "Extract text content from a Microsoft Word (.docx) file. Useful for reading documentation or forensics files in DOCX format.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to the .docx file",
				},
			},
			"required": []string{"path"},
		},
		Handler:  toolReadDocx,
		Mutating: false,
	})
}

// ============================================================================
// PCAP Analysis (Pure Go implementation)
// ============================================================================

// pcapGlobalHeader represents the global header of a pcap file
type pcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// pcapPacketHeader represents a packet header in pcap
type pcapPacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

func toolAnalyzePcap(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	data, err := os.ReadFile(params.Path)
	if err != nil {
		return "", fmt.Errorf("failed to read pcap file: %w", err)
	}

	return analyzePcapData(data)
}

func analyzePcapData(data []byte) (string, error) {
	if len(data) < 24 {
		return "", fmt.Errorf("file too small to be a valid pcap")
	}

	var sb strings.Builder
	sb.WriteString("=== PCAP ANALYSIS ===\n\n")

	// Check magic number to determine byte order
	magic := binary.LittleEndian.Uint32(data[0:4])
	var byteOrder binary.ByteOrder
	
	switch magic {
	case 0xa1b2c3d4: // Standard pcap, little endian
		byteOrder = binary.LittleEndian
		sb.WriteString("Format: Standard PCAP (little endian)\n")
	case 0xd4c3b2a1: // Standard pcap, big endian
		byteOrder = binary.BigEndian
		sb.WriteString("Format: Standard PCAP (big endian)\n")
	case 0xa1b23c4d: // Nanosecond pcap, little endian
		byteOrder = binary.LittleEndian
		sb.WriteString("Format: Nanosecond PCAP (little endian)\n")
	case 0x4d3cb2a1: // Nanosecond pcap, big endian
		byteOrder = binary.BigEndian
		sb.WriteString("Format: Nanosecond PCAP (big endian)\n")
	case 0x0a0d0d0a: // PCAPNG
		return analyzePcapNG(data)
	default:
		return "", fmt.Errorf("unknown pcap format (magic: 0x%x)", magic)
	}

	// Parse global header
	var header pcapGlobalHeader
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, byteOrder, &header); err != nil {
		return "", fmt.Errorf("failed to parse pcap header: %w", err)
	}

	sb.WriteString(fmt.Sprintf("Version: %d.%d\n", header.VersionMajor, header.VersionMinor))
	sb.WriteString(fmt.Sprintf("Snap Length: %d\n", header.SnapLen))
	sb.WriteString(fmt.Sprintf("Link Type: %d\n\n", header.Network))

	// Parse packets
	offset := 24 // After global header
	packetCount := 0
	connections := make(map[string]int)
	protocols := make(map[string]int)
	var findings []string

	for offset+16 <= len(data) && packetCount < 1000 { // Limit to first 1000 packets
		// Read packet header
		pktHeader := pcapPacketHeader{
			TsSec:   byteOrder.Uint32(data[offset:]),
			TsUsec:  byteOrder.Uint32(data[offset+4:]),
			InclLen: byteOrder.Uint32(data[offset+8:]),
			OrigLen: byteOrder.Uint32(data[offset+12:]),
		}
		offset += 16

		if offset+int(pktHeader.InclLen) > len(data) {
			break
		}

		packetData := data[offset : offset+int(pktHeader.InclLen)]
		offset += int(pktHeader.InclLen)
		packetCount++

		// Parse Ethernet frame (if link type is Ethernet)
		if header.Network == 1 && len(packetData) >= 14 {
			etherType := binary.BigEndian.Uint16(packetData[12:14])
			
			if etherType == 0x0800 && len(packetData) >= 34 { // IPv4
				// Parse IP header
				ipHeader := packetData[14:]
				if len(ipHeader) >= 20 {
					protocol := ipHeader[9]
					srcIP := fmt.Sprintf("%d.%d.%d.%d", ipHeader[12], ipHeader[13], ipHeader[14], ipHeader[15])
					dstIP := fmt.Sprintf("%d.%d.%d.%d", ipHeader[16], ipHeader[17], ipHeader[18], ipHeader[19])
					
					ihl := (ipHeader[0] & 0x0F) * 4
					transportData := ipHeader[ihl:]

					var srcPort, dstPort uint16
					var protoName string

					switch protocol {
					case 6: // TCP
						protoName = "TCP"
						if len(transportData) >= 4 {
							srcPort = binary.BigEndian.Uint16(transportData[0:2])
							dstPort = binary.BigEndian.Uint16(transportData[2:4])
						}
					case 17: // UDP
						protoName = "UDP"
						if len(transportData) >= 4 {
							srcPort = binary.BigEndian.Uint16(transportData[0:2])
							dstPort = binary.BigEndian.Uint16(transportData[2:4])
						}
					case 1:
						protoName = "ICMP"
					default:
						protoName = fmt.Sprintf("IP/%d", protocol)
					}

					protocols[protoName]++

					if srcPort > 0 || dstPort > 0 {
						connKey := fmt.Sprintf("%s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
						connections[connKey]++

						// Check for interesting ports
						for _, port := range []uint16{srcPort, dstPort} {
							switch port {
							case 21:
								protocols["FTP"]++
							case 23:
								protocols["Telnet"]++
							case 25:
								protocols["SMTP"]++
							case 80:
								protocols["HTTP"]++
							case 443:
								protocols["HTTPS"]++
							case 22:
								protocols["SSH"]++
							case 3306:
								protocols["MySQL"]++
							case 5432:
								protocols["PostgreSQL"]++
							}
						}
					}

					// Search for credentials in payload
					if len(transportData) > 20 {
						payload := string(transportData[20:])
						payloadLower := strings.ToLower(payload)
						
						// Look for FTP credentials
						if strings.Contains(payloadLower, "user ") || strings.Contains(payloadLower, "pass ") {
							// Extract the credential
							lines := strings.Split(payload, "\r\n")
							for _, line := range lines {
								lineLower := strings.ToLower(line)
								if strings.HasPrefix(lineLower, "user ") {
									findings = append(findings, fmt.Sprintf("FTP Username: %s", strings.TrimPrefix(line, "USER ")))
								}
								if strings.HasPrefix(lineLower, "pass ") {
									findings = append(findings, fmt.Sprintf("FTP Password: %s", strings.TrimPrefix(line, "PASS ")))
								}
							}
						}

						// Look for HTTP auth
						if strings.Contains(payloadLower, "authorization:") {
							findings = append(findings, "HTTP Authorization header detected")
						}

						// Look for plaintext passwords
						if strings.Contains(payloadLower, "password=") || strings.Contains(payloadLower, "passwd=") || strings.Contains(payloadLower, "pwd=") {
							findings = append(findings, "Plaintext password parameter detected in HTTP traffic")
						}
					}
				}
			}
		}
	}

	sb.WriteString(fmt.Sprintf("Total Packets Analyzed: %d\n\n", packetCount))

	// Report protocols
	sb.WriteString("PROTOCOLS DETECTED:\n")
	for proto, count := range protocols {
		sb.WriteString(fmt.Sprintf("  %s: %d packets\n", proto, count))
	}
	sb.WriteString("\n")

	// Report top connections (limit to 20)
	sb.WriteString("TOP CONNECTIONS:\n")
	connCount := 0
	for conn, count := range connections {
		if connCount >= 20 {
			sb.WriteString(fmt.Sprintf("  ... and %d more connections\n", len(connections)-20))
			break
		}
		sb.WriteString(fmt.Sprintf("  %s (%d packets)\n", conn, count))
		connCount++
	}
	sb.WriteString("\n")

	// Report findings
	if len(findings) > 0 {
		sb.WriteString("🔍 INTERESTING FINDINGS:\n")
		seen := make(map[string]bool)
		for _, finding := range findings {
			if !seen[finding] {
				sb.WriteString(fmt.Sprintf("  ⚠️ %s\n", finding))
				seen[finding] = true
			}
		}
	} else {
		sb.WriteString("No obvious credentials or sensitive data found in plaintext.\n")
		sb.WriteString("Consider using Wireshark for deeper analysis if available.\n")
	}

	return sb.String(), nil
}

func analyzePcapNG(data []byte) (string, error) {
	var sb strings.Builder
	sb.WriteString("=== PCAPNG ANALYSIS ===\n\n")
	sb.WriteString("Format: PCAP-NG (Next Generation)\n")
	sb.WriteString("Note: Basic analysis - for full details, use Wireshark\n\n")

	// PCAPNG is more complex - do basic string analysis for credentials
	content := string(data)
	contentLower := strings.ToLower(content)

	var findings []string

	// Search for FTP credentials
	if strings.Contains(contentLower, "user ") {
		userRegex := regexp.MustCompile(`(?i)USER ([^\r\n]+)`)
		if matches := userRegex.FindAllStringSubmatch(content, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) > 1 && len(m[1]) > 0 && len(m[1]) < 50 {
					findings = append(findings, fmt.Sprintf("Potential FTP Username: %s", m[1]))
				}
			}
		}
	}

	if strings.Contains(contentLower, "pass ") {
		passRegex := regexp.MustCompile(`(?i)PASS ([^\r\n]+)`)
		if matches := passRegex.FindAllStringSubmatch(content, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) > 1 && len(m[1]) > 0 && len(m[1]) < 50 {
					findings = append(findings, fmt.Sprintf("Potential FTP Password: %s", m[1]))
				}
			}
		}
	}

	// Search for HTTP credentials
	if strings.Contains(contentLower, "password=") {
		findings = append(findings, "HTTP password parameter detected")
	}

	// Report findings
	if len(findings) > 0 {
		sb.WriteString("🔍 INTERESTING FINDINGS:\n")
		seen := make(map[string]bool)
		for _, finding := range findings {
			if !seen[finding] {
				sb.WriteString(fmt.Sprintf("  ⚠️ %s\n", finding))
				seen[finding] = true
			}
		}
	} else {
		sb.WriteString("No obvious credentials found in quick scan.\n")
	}

	sb.WriteString("\nFor full protocol analysis, use: tshark -r <file> (if available)\n")

	return sb.String(), nil
}

// ============================================================================
// PDF Reader (Pure Go implementation)
// ============================================================================

func toolReadPDF(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	data, err := os.ReadFile(params.Path)
	if err != nil {
		return "", fmt.Errorf("failed to read PDF file: %w", err)
	}

	return extractPDFText(data)
}

func extractPDFText(data []byte) (string, error) {
	content := string(data)

	// Verify it's a PDF
	if !strings.HasPrefix(content, "%PDF") {
		return "", fmt.Errorf("not a valid PDF file")
	}

	var sb strings.Builder
	sb.WriteString("=== PDF TEXT EXTRACTION ===\n\n")

	// Extract text from stream objects
	// This is a simplified extraction that handles common cases

	var extractedTexts []string

	// Method 1: Look for text in BT...ET blocks (text objects)
	btRegex := regexp.MustCompile(`BT\s*(.*?)\s*ET`)
	btMatches := btRegex.FindAllStringSubmatch(content, -1)
	for _, match := range btMatches {
		if len(match) > 1 {
			text := extractTextFromBTBlock(match[1])
			if text != "" {
				extractedTexts = append(extractedTexts, text)
			}
		}
	}

	// Method 2: Look for text in parentheses after Tj or TJ operators
	tjRegex := regexp.MustCompile(`\(([^)]+)\)\s*Tj`)
	tjMatches := tjRegex.FindAllStringSubmatch(content, -1)
	for _, match := range tjMatches {
		if len(match) > 1 {
			text := decodePDFString(match[1])
			if text != "" {
				extractedTexts = append(extractedTexts, text)
			}
		}
	}

	// Method 3: Look for stream content (for FlateDecode streams, we can't decode without zlib)
	// But we can find uncompressed streams
	streamRegex := regexp.MustCompile(`stream\r?\n([\s\S]*?)\r?\nendstream`)
	streamMatches := streamRegex.FindAllStringSubmatch(content, -1)
	for _, match := range streamMatches {
		if len(match) > 1 {
			// Check if it's readable text
			streamContent := match[1]
			if isPrintableText(streamContent) {
				// Extract any readable text
				readable := extractReadableText(streamContent)
				if readable != "" {
					extractedTexts = append(extractedTexts, readable)
				}
			}
		}
	}

	// Deduplicate and combine
	seen := make(map[string]bool)
	for _, text := range extractedTexts {
		text = strings.TrimSpace(text)
		if text != "" && !seen[text] && len(text) > 2 {
			seen[text] = true
			sb.WriteString(text)
			sb.WriteString("\n")
		}
	}

	result := sb.String()
	if len(result) < 50 {
		return "=== PDF TEXT EXTRACTION ===\n\nNote: This PDF may use compression or encoding that requires external tools.\nTry: pdftotext <file> - (if available)\n\nNo plaintext content could be extracted.", nil
	}

	return result, nil
}

func extractTextFromBTBlock(block string) string {
	var texts []string

	// Look for strings in parentheses
	parenRegex := regexp.MustCompile(`\(([^)]*)\)`)
	matches := parenRegex.FindAllStringSubmatch(block, -1)
	for _, match := range matches {
		if len(match) > 1 {
			text := decodePDFString(match[1])
			if text != "" {
				texts = append(texts, text)
			}
		}
	}

	return strings.Join(texts, " ")
}

func decodePDFString(s string) string {
	// Handle PDF escape sequences
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\r", "\r")
	s = strings.ReplaceAll(s, "\\t", "\t")
	s = strings.ReplaceAll(s, "\\(", "(")
	s = strings.ReplaceAll(s, "\\)", ")")
	s = strings.ReplaceAll(s, "\\\\", "\\")

	// Filter non-printable characters
	var result strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

func isPrintableText(s string) bool {
	printable := 0
	total := len(s)
	if total == 0 {
		return false
	}

	for _, b := range []byte(s) {
		if (b >= 32 && b < 127) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}

	return float64(printable)/float64(total) > 0.7
}

func extractReadableText(s string) string {
	var result strings.Builder
	var currentWord strings.Builder

	for _, r := range s {
		if r >= 32 && r < 127 {
			currentWord.WriteRune(r)
		} else if currentWord.Len() > 0 {
			word := currentWord.String()
			if len(word) > 2 { // Filter very short sequences
				result.WriteString(word)
				result.WriteString(" ")
			}
			currentWord.Reset()
		}
	}

	if currentWord.Len() > 2 {
		result.WriteString(currentWord.String())
	}

	return strings.TrimSpace(result.String())
}

// ============================================================================
// DOCX Reader (Pure Go implementation using archive/zip)
// ============================================================================

func toolReadDocx(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	return extractDocxText(params.Path)
}

func extractDocxText(path string) (string, error) {
	// Open the docx file (it's a ZIP archive)
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("failed to open docx file: %w", err)
	}
	defer r.Close()

	var sb strings.Builder
	sb.WriteString("=== DOCX TEXT EXTRACTION ===\n\n")

	// Look for the main document content
	for _, f := range r.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			content, err := io.ReadAll(rc)
			if err != nil {
				continue
			}

			// Extract text from XML
			text := extractTextFromDocxXML(string(content))
			sb.WriteString(text)
			break
		}
	}

	// Also check for headers/footers if main content is empty
	if sb.Len() < 50 {
		for _, f := range r.File {
			if strings.HasPrefix(f.Name, "word/header") || strings.HasPrefix(f.Name, "word/footer") {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				content, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					continue
				}

				text := extractTextFromDocxXML(string(content))
				if text != "" {
					sb.WriteString("\n--- ")
					sb.WriteString(f.Name)
					sb.WriteString(" ---\n")
					sb.WriteString(text)
				}
			}
		}
	}

	result := sb.String()
	if len(result) < 50 {
		return "=== DOCX TEXT EXTRACTION ===\n\nNo text content found in document.", nil
	}

	return result, nil
}

func extractTextFromDocxXML(xml string) string {
	var sb strings.Builder

	// Remove XML tags but preserve text content
	// DOCX uses <w:t> tags for text
	textRegex := regexp.MustCompile(`<w:t[^>]*>([^<]*)</w:t>`)
	matches := textRegex.FindAllStringSubmatch(xml, -1)

	for _, match := range matches {
		if len(match) > 1 {
			sb.WriteString(match[1])
		}
	}

	// Also handle paragraph breaks
	result := sb.String()

	// Look for paragraph markers and add newlines
	paragraphRegex := regexp.MustCompile(`</w:p>`)
	result = paragraphRegex.ReplaceAllString(result, "\n")

	// Clean up multiple newlines
	multiNewline := regexp.MustCompile(`\n{3,}`)
	result = multiNewline.ReplaceAllString(result, "\n\n")

	// Decode XML entities
	result = strings.ReplaceAll(result, "&amp;", "&")
	result = strings.ReplaceAll(result, "&lt;", "<")
	result = strings.ReplaceAll(result, "&gt;", ">")
	result = strings.ReplaceAll(result, "&quot;", "\"")
	result = strings.ReplaceAll(result, "&apos;", "'")

	return strings.TrimSpace(result)
}

