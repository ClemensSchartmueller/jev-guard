package session

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Session lock parameters. Variables so tests can shorten them.
var (
	lockTimeout = 2 * time.Second
	lockPoll    = 5 * time.Millisecond
	lockSleep   = time.Sleep
)

// sessionLockPath is the lock file guarding a session's read-modify-write.
// It does not end in ".json", so session scans ignore it.
func sessionLockPath(sessionID string) string {
	return SessionFilePath(sessionID) + ".lock"
}

// withSessionLock runs fn while holding an exclusive OS advisory lock on the
// session's lock file (flock on Unix, LockFileEx on Windows). Hook processes
// for one session (ingest, PostToolUse taint, end-turn, parallel subagents)
// run concurrently, so every writer that depends on the current state takes
// this lock.
//
// The operating system releases the lock when its holder exits, so a crashed
// process never leaves the session locked and no lock is ever broken by age:
// a live but slow holder keeps it. The lock file itself is never deleted,
// because unlinking a locked file would let a second process lock a new file
// at the same path. Acquisition gives up after lockTimeout.
func withSessionLock(sessionID string, fn func() error) error {
	if err := os.MkdirAll(GetSessionsDir(), 0700); err != nil {
		return fmt.Errorf("failed to create sessions directory: %w", err)
	}
	path := sessionLockPath(sessionID)
	deadline := time.Now().Add(lockTimeout)
	var f *os.File
	for {
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err == nil {
			locked, lockErr := tryLockFile(f)
			if locked {
				break
			}
			_ = f.Close()
			if lockErr != nil {
				return fmt.Errorf("failed to acquire session lock %s: %w", path, lockErr)
			}
		} else if !retryable(err) {
			return fmt.Errorf("failed to open session lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w after %s waiting for session lock %s", ErrLockTimeout, lockTimeout, path)
		}
		lockSleep(lockPoll)
	}
	defer func() {
		_ = unlockFile(f)
		_ = f.Close()
	}()
	return fn()
}

// ErrLockTimeout is returned when another process held the session lock for
// longer than the acquisition timeout.
var ErrLockTimeout = errors.New("timed out")
