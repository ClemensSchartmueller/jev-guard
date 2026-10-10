package transcript

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const convID = "abc-123"

func setup(t *testing.T, body string) (path, home string) {
	t.Helper()
	home = t.TempDir()
	dir := filepath.Join(home, ".gemini", "antigravity", "brain", convID, ".system_generated", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "transcript.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, home
}

const model = `{"type":"PLANNER_RESPONSE","source":"MODEL","status":"DONE","step_index":2,"content":"thinking"}` + "\n"

func user(text string) string {
	return `{"type":"USER_INPUT","source":"USER_EXPLICIT","status":"DONE","step_index":1,"content":"` + text + `"}` + "\n"
}

func TestLatestUserInput_FoundAmongModelRecords(t *testing.T) {
	p, h := setup(t, user("fix the bug")+model+model)
	got, err := LatestUserInput(p, convID, h)
	if err != nil || got != "fix the bug" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestLatestUserInput_LastWins(t *testing.T) {
	p, h := setup(t, user("first")+model+user("second")+model)
	got, err := LatestUserInput(p, convID, h)
	if err != nil || got != "second" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestLatestUserInput_PathOutsideExpected(t *testing.T) {
	_, h := setup(t, user("x"))
	other := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(other, []byte(user("x")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LatestUserInput(other, convID, h); err == nil {
		t.Fatal("expected error")
	}
}

func TestLatestUserInput_MismatchedConversationID(t *testing.T) {
	p, h := setup(t, user("x"))
	if _, err := LatestUserInput(p, "other-id", h); err == nil {
		t.Fatal("expected error")
	}
}

func TestLatestUserInput_TraversalID(t *testing.T) {
	p, h := setup(t, user("x"))
	for _, id := range []string{"../x", "a/b", "", strings.Repeat("a", 129)} {
		if _, err := LatestUserInput(p, id, h); err == nil {
			t.Errorf("expected error for id %q", id)
		}
	}
}

func TestLatestUserInput_TruncatedContent(t *testing.T) {
	rec := `{"type":"USER_INPUT","source":"USER_EXPLICIT","status":"DONE","content":"half","truncated_fields":["content"]}` + "\n"
	p, h := setup(t, user("older")+rec)
	if _, err := LatestUserInput(p, convID, h); err == nil || errors.Is(err, ErrNoUserInput) {
		t.Fatalf("expected truncation error, got %v", err)
	}
}

func TestLatestUserInput_NoUserInput(t *testing.T) {
	p, h := setup(t, model+model)
	if _, err := LatestUserInput(p, convID, h); !errors.Is(err, ErrNoUserInput) {
		t.Fatalf("got %v", err)
	}
}

func TestLatestUserInput_BoundedScan(t *testing.T) {
	line := `{"type":"GENERIC","source":"MODEL","content":"` + strings.Repeat("x", 900) + `"}` + "\n"
	filler := strings.Repeat(line, 10000)
	if len(filler) < 9<<20 {
		t.Fatalf("filler too small: %d", len(filler))
	}
	p, h := setup(t, user("ancient")+filler)
	if _, err := LatestUserInput(p, convID, h); !errors.Is(err, ErrNoUserInput) {
		t.Fatalf("got %v", err)
	}
}

func TestLatestUserInput_TrailingPartialLine(t *testing.T) {
	p, h := setup(t, user("hello")+model+`{"type":"USER_INPUT","source":"USER_EXP`)
	got, err := LatestUserInput(p, convID, h)
	if err != nil || got != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestLatestUserInput_LargeInputCapped(t *testing.T) {
	p, h := setup(t, user(strings.Repeat("a", 20000)))
	got, err := LatestUserInput(p, convID, h)
	if err != nil || len(got) != 8<<10 {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
}

func TestLatestUserInput_AcrossChunks(t *testing.T) {
	line := `{"type":"GENERIC","source":"MODEL","content":"` + strings.Repeat("y", 500) + `"}` + "\n"
	p, h := setup(t, user("early")+strings.Repeat(line, 600))
	got, err := LatestUserInput(p, convID, h)
	if err != nil || got != "early" {
		t.Fatalf("got %q, %v", got, err)
	}
}
