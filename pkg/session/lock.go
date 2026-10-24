package session

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Session lock parameters. Variables so tests can shorten them. A hook
// process holds the lock for a single read and rename, so a lock older than
// lockStaleAfter belongs to a crashed process and is broken.
var (
	lockTimeout    = 2 * time.Second
	lockPoll       = 5 * time.Millisecond
	lockStaleAfter = 10 * time.Second
	lockSleep      = time.Sleep
)

// sessionLockPath is the lock file guarding a session's read-modify-write.
// It does not end in ".json", so session scans ignore it.
func sessionLockPath(sessionID string) string {
	return SessionFilePath(sessionID) + ".lock"
}

// withSessionLock runs fn while holding an exclusive lock file for the
// session. Hook processes for one session (ingest, PostToolUse taint,
// end-turn, parallel subagents) run concurrently, so every writer that
// depends on the current state takes this lock. Acquisition uses O_EXCL,
// which works across processes on every platform.
func withSessionLock(sessionID string, fn func() error) error {
	if err := os.MkdirAll(GetSessionsDir(), 0700); err != nil {
		return fmt.Errorf("failed to create sessions directory: %w", err)
	}
	path := sessionLockPath(sessionID)
	deadline := time.Now().Add(lockTimeout)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_ = f.Close()
			break
		}
		if !errors.Is(err, os.ErrExist) && !retryable(err) {
			return fmt.Errorf("failed to acquire session lock: %w", err)
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > lockStaleAfter {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for session lock %s", lockTimeout, path)
		}
		lockSleep(lockPoll)
	}
	defer os.Remove(path)
	return fn()
}
