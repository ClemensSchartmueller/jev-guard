package harness

import "testing"

// Path arguments are kept as given: a name or directory that differs from another only by
// surrounding whitespace is a different entry.
func TestPathArgumentsAreNotTrimmed(t *testing.T) {
	if got := extractCwd(map[string]interface{}{"cwd": "/ws/sub "}); got != "/ws/sub " {
		t.Fatalf("cwd = %q, want the raw argument", got)
	}
	if _, got := extractCommandAndTarget(map[string]interface{}{"file_path": " "}); got != " " {
		t.Fatalf("target = %q, want the whitespace-only argument kept", got)
	}
	call := &NormalizedToolCall{TargetPath: "a ", RawArgs: map[string]interface{}{"file_path": "a "}}
	if !HasSingleTargetArg(call, "file_path") {
		t.Fatal("raw argument equal to TargetPath was rejected")
	}
	call.RawArgs["file_path"] = "a"
	if HasSingleTargetArg(call, "file_path") {
		t.Fatal("argument differing from TargetPath by whitespace was accepted")
	}
}
