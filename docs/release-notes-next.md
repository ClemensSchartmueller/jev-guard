# Next release (draft)

Changes since v0.4.0. Assign a version and confirm CI before publishing. The v0.4.0 notes are in the [GitHub release](https://github.com/ClemensSchartmueller/jev-guard/releases/tag/v0.4.0).

## Fixes

- Clean up files left by abandoned sessions (#75). Per-session lock files (`<session>.json.lock`) previously accumulated, one per session ID, and expired taint and abort markers stayed on disk until a clear. `end-turn` and `status` now run a cleanup sweep at most once an hour. It deletes markers and session files older than 48 hours, longer than the largest configurable intent TTL, and lock files that have been idle for 7 days once their session file and markers are gone. Every removal happens under the session's lock, taken without waiting, so active sessions are skipped. Lock acquisition now verifies that the lock path still names the locked file and retries otherwise, so removing a lock file never lets two hooks lock the same session at once. Deletion errors, such as Windows refusing to delete an open file, are ignored and never fail a hook.

## Upgrade notes

- No action is needed. The first `end-turn` or `status` after upgrading removes files of sessions abandoned before the upgrade, a bounded amount per sweep (at most 1024 directory entries, 1024 filesystem calls on 128 sessions, and about 150 ms, checked before each filesystem call), resuming where the previous sweep stopped.

## Remaining issue scope

- #77: trust-path canonicalization remains deferred because it requires migration design.
