// Package eaclogchecker implements verification and signing of Exact Audio Copy
// (EAC) log checksums using Rijndael-256 in CBC mode with a 256-bit block size.
package eaclogchecker

import (
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Nirzak/eac-logchecker/rijndael256"
)

const eacKey = "9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9"

// Result holds the outcome for a single log entry.
type Result struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

// log holds a single EAC log entry and its computed/expected checksums.
// Unexported; callers interact only through CheckChecksum and SignLog.
type log struct {
	text         string
	unsignedText string
	version      []string
	modified     bool
	oldChecksum  string
	checksum     string
}

// eacChecksum computes the Rijndael-256 CBC checksum of l.unsignedText
// and stores the uppercase hex result in l.checksum.
func eacChecksum(l *log) error {
	text := l.unsignedText

	// Strip newlines (the algorithm ignores them).
	text = strings.ReplaceAll(text, "\r", "")
	text = strings.ReplaceAll(text, "\n", "")

	// Strip BOMs (fuzzing revealed these are also ignored).
	text = strings.ReplaceAll(text, "\ufeff", "")
	text = strings.ReplaceAll(text, "\ufffe", "")

	// Build the Rijndael-256 cipher.
	keyBytes, err := hex.DecodeString(eacKey)
	if err != nil {
		return fmt.Errorf("invalid EAC key: %w", err)
	}
	cipher, err := rijndael256.NewCipher(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encode as UTF-16-LE.
	runes := []rune(text)
	u16 := utf16.Encode(runes)
	plaintext := make([]byte, len(u16)*2)
	for i, r := range u16 {
		plaintext[2*i] = byte(r)
		plaintext[2*i+1] = byte(r >> 8)
	}

	// IV is all zeroes; start checksum block as zeroes.
	const blockSize = 32
	checksum := make([]byte, blockSize)
	ciphertext := make([]byte, blockSize)

	// CBC mode: process each 32-byte block.
	// If plaintext is empty the loop body never executes, matching Python behaviour.
	for i := 0; i < len(plaintext); i += blockSize {
		// Safe slice: cap at len(plaintext), then zero-pad to blockSize.
		end := i + blockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		plainBlock := plaintext[i:end]

		// Zero-pad the last block if necessary.
		var block [blockSize]byte
		copy(block[:], plainBlock)

		// XOR with previous ciphertext (CBC).
		var cbcBlock [blockSize]byte
		for j := 0; j < blockSize; j++ {
			cbcBlock[j] = checksum[j] ^ block[j]
		}

		cipher.Encrypt(ciphertext, cbcBlock[:])
		copy(checksum, ciphertext)
	}

	l.checksum = strings.ToUpper(hex.EncodeToString(checksum))
	return nil
}

// versionLineRe matches the "Exact Audio Copy V1.0 beta 1" header line.
var versionLineRe = regexp.MustCompile(`^Exact Audio Copy`)

// checksumBlockRe matches the trailing checksum block, e.g.:
//
//	\n\n==== Log checksum A3B4C5... ====
var checksumBlockRe = regexp.MustCompile(`\n\n==== (.*?) ([A-Z0-9]+) ====`)

// alphaStartRe matches lines that start with a letter (used to stop version search).
var alphaStartRe = regexp.MustCompile(`^[a-zA-Z]`)

// extractInfo parses l.text to find the EAC version and strip/record the
// existing checksum block, storing the unsigned portion in l.unsignedText.
func extractInfo(l *log) {
	if len(l.text) == 0 {
		return
	}

	// Find version on the first header line.
	for _, line := range strings.Split(l.text, "\n") {
		if versionLineRe.MatchString(line) {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				l.version = fields[3:6]
			}
		} else if alphaStartRe.MatchString(line) {
			break
		}
	}

	// Find and strip the checksum block.
	if match := checksumBlockRe.FindStringSubmatch(l.text); match != nil {
		labelPart := match[1]    // e.g. "Log checksum"
		checksumPart := match[2] // e.g. "A3B4C5..."

		search := "\n\n==== " + labelPart
		parts := strings.SplitN(l.text, search, 2)
		if len(parts) == 2 {
			l.unsignedText = parts[0]
			l.oldChecksum = checksumPart
		}
	}
}

// eacVerify runs extractInfo then eacChecksum on the log entry.
func eacVerify(l *log) error {
	extractInfo(l)
	return eacChecksum(l)
}

// separatorRe matches the 60-dash separator between multi-disc logs.
var separatorRe = regexp.MustCompile(`[^-]-{60}[^-]`)

// splitRe splits the full text on checksum-block boundaries so individual
// log entries (and their checksum blocks) can be paired up.
var splitRe = regexp.MustCompile(`(\n\n==== .* [A-Z0-9]+ ====)`)

// getLogs decodes the raw UTF-16-LE bytes of an EAC log file and returns
// one log entry per ripping session contained in the file.
func getLogs(data []byte) ([]*log, error) {
	// Decode UTF-16-LE.
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
	}
	text := string(utf16.Decode(u16))

	// Strip BOM.
	text = strings.TrimPrefix(text, "\ufeff")

	// Normalise line endings (makes our own regexes simpler).
	text = strings.ReplaceAll(text, "\r\n", "\n")

	// Null bytes corrupt the checksum — truncate at the first one.
	if idx := strings.Index(text, "\x00"); idx != -1 {
		text = text[:idx]
	}

	// EAC crashes on lines > 2^13 chars.
	for _, line := range strings.Split(text, "\n") {
		if len([]rune(line))+1 > 1<<13 {
			return nil, fmt.Errorf("EAC cannot handle lines longer than 2^13 chars")
		}
	}

	// Split on checksum markers (keeps delimiters as separate elements).
	splits := splitRe.Split(text, -1)
	delimiters := splitRe.FindAllString(text, -1)

	// Reconstruct interleaved [body, delimiter] pairs, filtering empty pieces.
	var pieces []string
	for i, s := range splits {
		if strings.TrimSpace(s) != "" {
			pieces = append(pieces, s)
		}
		if i < len(delimiters) {
			pieces = append(pieces, delimiters[i])
		}
	}

	var logs []*log

	if len(pieces) > 1 {
		length := len(pieces)
		if length%2 == 1 {
			length--
		}
		for i := 0; i < length; i += 2 {
			l := &log{
				text:         pieces[i] + pieces[i+1],
				unsignedText: pieces[i] + pieces[i+1],
			}
			if i > 0 {
				// Remove the inter-disc separator from subsequent entries.
				result := separatorRe.ReplaceAllStringFunc(l.text, func(m string) string {
					return ""
				})
				count := len(separatorRe.FindAllString(l.text, -1))
				if count == 0 {
					l.modified = true
				} else {
					l.text = result
					l.unsignedText = result
				}
			}
			logs = append(logs, l)
		}
		for i := length; i < len(pieces); i++ {
			logs = append(logs, &log{
				text:         pieces[i],
				unsignedText: pieces[i],
			})
		}
	} else if len(pieces) == 1 {
		logs = append(logs, &log{
			text:         pieces[0],
			unsignedText: pieces[0],
		})
	}

	return logs, nil
}

// CheckChecksum verifies the EAC checksum(s) in the given log file and
// returns one Result per log entry found in the file.
func CheckChecksum(path string) []Result {
	var output []Result

	data, err := os.ReadFile(path)
	if err != nil {
		output = append(output, Result{
			Status:  "ERROR",
			Message: "Could not find logfile to examine.",
		})
		return output
	}

	logs, err := getLogs(data)
	if err != nil {
		// Runtime errors (e.g. line too long) → treat as no checksum.
		output = append(output, Result{
			Status:  "NO",
			Message: "Log entry has no checksum!",
		})
		return output
	}

	for _, l := range logs {
		if err := eacVerify(l); err != nil {
			output = append(output, Result{
				Status:  "NO",
				Message: "Log entry has no checksum!",
			})
			continue
		}

		var status, message string
		switch {
		case len(l.version) == 0 || l.oldChecksum == "":
			status = "NO"
			message = "Log entry has no checksum!"
		case l.modified || l.oldChecksum != l.checksum:
			status = "BAD"
			message = "Log entry was modified, checksum incorrect!"
		default:
			status = "OK"
			message = "Log entry is fine!"
		}

		output = append(output, Result{Status: status, Message: message})
	}

	return output
}

// ---------------------------------------------------------------------------
// Sign functionality
// ---------------------------------------------------------------------------

// minSignVersion is the minimum EAC version whose logs can be signed: V1.0 beta 1.
// beta == math.MaxInt means a full release (greater than any beta number).
var minSignVersion = eacSignVersion{major: 1, minor: 0, beta: 1}

// eacSignVersion holds a structurally parsed EAC version for comparison.
type eacSignVersion struct {
	major, minor, beta int
}

// atLeast reports whether v >= min using the same ordering as Python tuples.
func (v eacSignVersion) atLeast(min eacSignVersion) bool {
	switch {
	case v.major != min.major:
		return v.major > min.major
	case v.minor != min.minor:
		return v.minor > min.minor
	default:
		return v.beta >= min.beta
	}
}

// parseSignVersion parses the EAC version from the header line, e.g.
// "Exact Audio Copy V1.0 beta 1 from ..."
// Release versions (no "beta") have beta = math.MaxInt, so they compare
// greater than any beta version, matching Python's float('+inf') behaviour.
func parseSignVersion(line string) (eacSignVersion, bool) {
	s := strings.TrimPrefix(line, "Exact Audio Copy ")
	if idx := strings.Index(s, " from"); idx != -1 {
		s = s[:idx]
	}
	// Strip leading 'V'
	if len(s) < 2 || s[0] != 'V' {
		return eacSignVersion{}, false
	}
	s = s[1:]

	var majorMinorStr, betaStr string
	isBeta := false
	if parts := strings.SplitN(s, " beta ", 2); len(parts) == 2 {
		majorMinorStr = parts[0]
		// Beta number may be followed by more text; take the first token.
		betaStr = strings.Fields(parts[1])[0]
		isBeta = true
	} else {
		majorMinorStr = strings.Fields(s)[0]
	}

	mm := strings.SplitN(majorMinorStr, ".", 2)
	if len(mm) != 2 {
		return eacSignVersion{}, false
	}
	major, err1 := strconv.Atoi(strings.TrimSpace(mm[0]))
	minor, err2 := strconv.Atoi(strings.TrimSpace(mm[1]))
	if err1 != nil || err2 != nil {
		return eacSignVersion{}, false
	}

	beta := math.MaxInt
	if isBeta {
		b, err := strconv.Atoi(strings.TrimSpace(betaStr))
		if err != nil {
			return eacSignVersion{}, false
		}
		beta = b
	}

	return eacSignVersion{major: major, minor: minor, beta: beta}, true
}

// signChecksumDelimiter is the CRLF-aware separator used in raw (non-normalised) log text.
const signChecksumDelimiter = "\r\n\r\n==== Log checksum"

// signExtractInfo extracts the unsigned text (with CRLF preserved) and the
// parsed EAC version from a raw decoded log string.
// If an existing checksum block is present it is stripped, matching the
// Python eac.py extract_info() behaviour.
func signExtractInfo(text string) (unsignedText string, ver *eacSignVersion) {
	// Find the version line, stopping at the first non-header letter line.
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "Exact Audio Copy") {
			if v, ok := parseSignVersion(line); ok {
				v := v // capture
				ver = &v
			}
		} else if alphaStartRe.MatchString(line) {
			break
		}
	}

	// Strip any existing checksum block so we get clean unsigned text.
	unsignedText = text
	if idx := strings.Index(text, signChecksumDelimiter); idx != -1 {
		unsignedText = text[:idx]
	}
	return
}

// SignLog reads inputPath, strips any existing checksum, computes a fresh one,
// and writes the signed log (UTF-16-LE with BOM) to outputPath.
// When force is false the function refuses to sign logs from EAC versions
// older than V1.0 beta 1.
func SignLog(inputPath, outputPath string, force bool) error {
	rawData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", inputPath, err)
	}

	// Decode UTF-16-LE.
	if len(rawData)%2 != 0 {
		rawData = append(rawData, 0)
	}
	u16in := make([]uint16, len(rawData)/2)
	for i := range u16in {
		u16in[i] = uint16(rawData[2*i]) | uint16(rawData[2*i+1])<<8
	}
	text := string(utf16.Decode(u16in))

	// Strip BOM.
	text = strings.TrimPrefix(text, "\ufeff")

	// Truncate at the first null byte.
	if idx := strings.Index(text, "\x00"); idx != -1 {
		text = text[:idx]
	}

	// Guard against lines too long for EAC.
	for _, line := range strings.Split(text, "\n") {
		if len([]rune(line))+1 > 1<<13 {
			return fmt.Errorf("EAC cannot handle lines longer than 2^13 chars")
		}
	}

	unsignedText, ver := signExtractInfo(text)

	// Version check (skip when force is set).
	if !force {
		if ver == nil || !ver.atLeast(minSignVersion) {
			return fmt.Errorf("EAC version is too old to be signed (use --force to override)")
		}
	}

	// Compute the checksum over the unsigned text.
	l := &log{unsignedText: unsignedText}
	if err := eacChecksum(l); err != nil {
		return fmt.Errorf("checksum computation failed: %w", err)
	}

	// Build the signed text: unsigned body + CRLF checksum block.
	signed := unsignedText + "\r\n\r\n==== Log checksum " + l.checksum + " ====\r\n"

	// Encode as UTF-16-LE and prepend the UTF-16 LE BOM (0xFF 0xFE).
	runes := []rune(signed)
	u16out := utf16.Encode(runes)
	out := make([]byte, 2+len(u16out)*2)
	out[0] = 0xff // BOM
	out[1] = 0xfe
	for i, r := range u16out {
		out[2+2*i] = byte(r)
		out[2+2*i+1] = byte(r >> 8)
	}

	if err := os.WriteFile(outputPath, out, 0644); err != nil {
		return fmt.Errorf("cannot write %s: %w", outputPath, err)
	}

	return nil
}
