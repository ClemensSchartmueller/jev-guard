// Package transcript extracts the latest explicit user request from an
// Antigravity conversation transcript. The transcript format is not officially
// documented, so every failure mode here is reported as an error and callers
// are expected to fall back to stateless gating.
package transcript

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	chunkSize    = 64 << 10
	maxScanBytes = 8 << 20
	maxTextBytes = 8 << 10
)

// ErrNoUserInput means no explicit user message was found in the scanned window.
var ErrNoUserInput = errors.New("no user input found in transcript")

// ErrUnusableUserInput means the latest explicit user message exists but carries no usable text (empty, non-text, missing, malformed, truncated, or over the size cap).
var ErrUnusableUserInput = errors.New("latest user input in transcript has no usable text")

var conversationIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

type record struct {
	Type            string          `json:"type"`
	Source          string          `json:"source"`
	Content         json.RawMessage `json:"content"`
	TruncatedFields json.RawMessage `json:"truncated_fields"`
}

// LatestUserInput returns the content of the last USER_INPUT/USER_EXPLICIT record
// in the transcript at path. The path must be the canonical transcript location of
// conversationID under home, otherwise an error is returned. If the latest explicit
// user record has no usable text, ErrUnusableUserInput (possibly wrapped) is returned
// and older messages are never used.
func LatestUserInput(path, conversationID, home string) (string, error) {
	resolved, err := validatePath(path, conversationID, home)
	if err != nil {
		return "", err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", fmt.Errorf("open transcript: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat transcript: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("transcript is not a regular file")
	}
	return scanBackwards(f, info.Size())
}

func validatePath(path, conversationID, home string) (string, error) {
	if !conversationIDPattern.MatchString(conversationID) {
		return "", errors.New("invalid conversation id")
	}
	if strings.TrimSpace(path) == "" || strings.TrimSpace(home) == "" {
		return "", errors.New("transcript path or home directory is empty")
	}
	expected := filepath.Join(home, ".gemini", "antigravity", "brain", conversationID, ".system_generated", "logs", "transcript.jsonl")
	got, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve transcript path: %w", err)
	}
	want, err := filepath.EvalSymlinks(expected)
	if err != nil {
		return "", fmt.Errorf("resolve expected transcript path: %w", err)
	}
	if !pathsEqual(got, want) {
		return "", errors.New("transcript path is not the expected location for this conversation")
	}
	info, err := os.Stat(got)
	if err != nil {
		return "", fmt.Errorf("stat transcript: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("transcript is not a regular file")
	}
	return got, nil
}

func pathsEqual(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func scanBackwards(r io.ReaderAt, size int64) (string, error) {
	var carry []byte // start of a line whose beginning has not been read yet
	pos := size
	var scanned int64
	for pos > 0 && scanned < maxScanBytes {
		n := int64(chunkSize)
		if n > pos {
			n = pos
		}
		if rest := maxScanBytes - scanned; n > rest {
			n = rest
		}
		buf := make([]byte, n+int64(len(carry)))
		if _, err := r.ReadAt(buf[:n], pos-n); err != nil && err != io.EOF {
			return "", fmt.Errorf("read transcript: %w", err)
		}
		copy(buf[n:], carry)
		pos -= n
		scanned += n

		lines := bytes.Split(buf, []byte{'\n'})
		start := 0
		carry = nil
		if pos > 0 {
			// The first element may be an incomplete line. Keep it for the next
			// chunk unless the scan limit is reached, in which case drop it.
			start = 1
			if scanned < maxScanBytes {
				carry = lines[0]
			}
		}
		for i := len(lines) - 1; i >= start; i-- {
			text, found, err := inspectLine(lines[i])
			if err != nil {
				return "", err
			}
			if found {
				return text, nil
			}
		}
	}
	return "", ErrNoUserInput
}

// inspectLine reports whether line is the latest explicit user record. found is
// true for the first such record; it is returned with either text or an error,
// so an unusable latest record stops the backward scan instead of falling back.
func inspectLine(line []byte) (string, bool, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return "", false, nil
	}
	var rec record
	if err := json.Unmarshal(line, &rec); err != nil {
		// Fail closed if a malformed line may be an explicit user record.
		if bytes.Contains(line, []byte(`"USER_INPUT"`)) {
			return "", true, ErrUnusableUserInput
		}
		return "", false, nil
	}
	if rec.Type != "USER_INPUT" || rec.Source != "USER_EXPLICIT" {
		return "", false, nil
	}
	if bytes.Contains(bytes.ToLower(rec.TruncatedFields), []byte("content")) {
		return "", true, fmt.Errorf("latest user input is truncated in transcript: %w", ErrUnusableUserInput)
	}
	var content string
	if len(rec.Content) == 0 || json.Unmarshal(rec.Content, &content) != nil || strings.TrimSpace(content) == "" {
		return "", true, ErrUnusableUserInput
	}
	if len(content) > maxTextBytes {
		return "", true, fmt.Errorf("latest user input exceeds %d bytes: %w", maxTextBytes, ErrUnusableUserInput)
	}
	return content, true, nil
}
