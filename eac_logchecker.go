// eac_logchecker.go — Go port of eac_logchecker.py
// Verifies and resigns EAC (Exact Audio Copy) log checksums.
// The checksum algorithm uses Rijndael-256 in CBC mode with a 256-bit block size.

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf16"

	"eac-logchecker/rijndael256"
)

const (
	version = "0.8.1"
	eacKey  = "9378716cf13e4265ae55338e940b376184da389e50647726b35f6f341ee3efd9"
)

// Result holds the outcome for a single log entry.
type Result struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

// Log holds a single EAC log entry and its computed/expected checksums.
type Log struct {
	text        string
	unsignedText string
	version     []string
	modified    bool
	oldChecksum string
	checksum    string
}

// eacChecksum computes the Rijndael-256 CBC checksum of log.unsignedText
// and stores the uppercase hex result in log.checksum.
func eacChecksum(log *Log) error {
	text := log.unsignedText

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

	// CBC mode: process each 32-byte block (Python: range(0, len(plaintext), 32)).
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

	log.checksum = strings.ToUpper(hex.EncodeToString(checksum))
	return nil
}

// versionLineRe matches the "Exact Audio Copy V1.0 beta 1" header line.
var versionLineRe = regexp.MustCompile(`^Exact Audio Copy`)

// checksumBlockRe matches the trailing checksum block, e.g.:
//   \n\n==== Log checksum A3B4C5... ====
var checksumBlockRe = regexp.MustCompile(`\n\n==== (.*?) ([A-Z0-9]+) ====`)

// alphaStartRe matches lines that start with a letter (used to stop version search).
var alphaStartRe = regexp.MustCompile(`^[a-zA-Z]`)

// extractInfo parses log.text to find the EAC version and strip/record the
// existing checksum block, storing the unsigned portion in log.unsignedText.
func extractInfo(log *Log) {
	if len(log.text) == 0 {
		return
	}

	// Find version on the first header line.
	for _, line := range strings.Split(log.text, "\n") {
		if versionLineRe.MatchString(line) {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				log.version = fields[3:6]
			}
		} else if alphaStartRe.MatchString(line) {
			break
		}
	}

	// Find and strip the checksum block.
	match := checksumBlockRe.FindStringSubmatchIndex(log.text)
	if match != nil {
		fullMatch := checksumBlockRe.FindStringSubmatch(log.text)
		labelPart := fullMatch[1] // e.g. "Log checksum"
		checksumPart := fullMatch[2]

		search := "\n\n==== " + labelPart
		parts := strings.SplitN(log.text, search, 2)
		if len(parts) == 2 {
			log.unsignedText = parts[0]
			// The checksum is the first token after the split point.
			afterSplit := strings.TrimSpace(parts[1])
			// checksumPart is already captured above.
			_ = afterSplit
			log.oldChecksum = checksumPart
		}
	}
}

// eacVerify runs extractInfo then eacChecksum on the log.
func eacVerify(log *Log) error {
	extractInfo(log)
	return eacChecksum(log)
}

// separatorRe matches the 60-dash separator between multi-disc logs.
var separatorRe = regexp.MustCompile(`[^-]-{60}[^-]`)

// splitRe splits the full text on checksum-block boundaries so individual
// log entries (and their checksum blocks) can be paired up.
var splitRe = regexp.MustCompile(`(\n\n==== .* [A-Z0-9]+ ====)`)

// getLogs decodes the raw UTF-16-LE bytes of an EAC log file and returns
// one Log per ripping session contained in the file.
func getLogs(data []byte) ([]*Log, error) {
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

	var logs []*Log

	if len(pieces) > 1 {
		length := len(pieces)
		if length%2 == 1 {
			length--
		}
		for i := 0; i < length; i += 2 {
			l := &Log{
				text:         pieces[i] + pieces[i+1],
				unsignedText: pieces[i] + pieces[i+1],
			}
			if i > 0 {
				// Remove the inter-disc separator from subsequent entries.
				result := separatorRe.ReplaceAllStringFunc(l.text, func(m string) string {
					return ""
				})
				// Count replacements manually.
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
			logs = append(logs, &Log{
				text:         pieces[i],
				unsignedText: pieces[i],
			})
		}
	} else if len(pieces) == 1 {
		logs = append(logs, &Log{
			text:         pieces[0],
			unsignedText: pieces[0],
		})
	}

	return logs, nil
}

// CheckChecksum verifies the EAC checksum(s) in the given log file and
// returns one Result per log entry.
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

	for _, log := range logs {
		if err := eacVerify(log); err != nil {
			output = append(output, Result{
				Status:  "NO",
				Message: "Log entry has no checksum!",
			})
			continue
		}

		var status, message string
		switch {
		case len(log.version) == 0 || log.oldChecksum == "":
			status = "NO"
			message = "Log entry has no checksum!"
		case log.modified || log.oldChecksum != log.checksum:
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

func main() {
	var (
		jsonFlag    = flag.Bool("json", false, "Output as JSON")
		versionFlag = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Println("eac-logchecker " + version)
		return
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: eac-logchecker [--json] [--version] <file>")
		os.Exit(1)
	}

	filePath := flag.Arg(0)

	if !*jsonFlag {
		fmt.Println("Log Integrity Checker   (C) 2010 by Andre Wiethoff")
		fmt.Println()
	}

	results := CheckChecksum(filePath)

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(results)
	} else {
		for i, r := range results {
			fmt.Printf("%d. %s\n", i+1, r.Message)
		}
	}
}
