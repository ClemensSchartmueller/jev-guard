package fastpath

import (
	"testing"

	"jev-guard/pkg/harness"
)

func TestFastPath_Catastrophic(t *testing.T) {
	filter := NewDefaultFilter()

	cases := []string{
		"rm -rf /",
		"rm -fr /*",
		":(){ :|:& };:",
		"format c:",
	}

	for _, cmd := range cases {
		call := &harness.NormalizedToolCall{
			ToolName: "Bash",
			Command:  cmd,
		}
		res := filter.Evaluate(call)
		if res == nil {
			t.Fatalf("expected catastrophic block for %q, got nil", cmd)
		}
		if res.Decision != harness.DecisionDeny {
			t.Errorf("expected DENY for %q, got %v", cmd, res.Decision)
		}
	}
}

func TestFastPath_SensitiveFiles(t *testing.T) {
	filter := NewDefaultFilter()

	call1 := &harness.NormalizedToolCall{
		ToolName: "Bash",
		Command:  "cat .env",
	}
	res1 := filter.Evaluate(call1)
	if res1 == nil || res1.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for .env, got %+v", res1)
	}

	call2 := &harness.NormalizedToolCall{
		ToolName:   "write_to_file",
		TargetPath: "/home/user/.ssh/id_rsa",
	}
	res2 := filter.Evaluate(call2)
	if res2 == nil || res2.Decision != harness.DecisionAsk {
		t.Errorf("expected ASK for id_rsa, got %+v", res2)
	}
}

func TestFastPath_SafeWhitelist(t *testing.T) {
	filter := NewDefaultFilter()

	call1 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git status",
	}
	res1 := filter.Evaluate(call1)
	if res1 == nil || res1.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for 'git status', got %+v", res1)
	}

	call2 := &harness.NormalizedToolCall{
		ToolName:   "view_file",
		TargetPath: "main.go",
	}
	res2 := filter.Evaluate(call2)
	if res2 == nil || res2.Decision != harness.DecisionAllow {
		t.Errorf("expected ALLOW for view_file, got %+v", res2)
	}

	// Should NOT allow if chained with mutator
	call3 := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "git status; rm -rf /",
	}
	res3 := filter.Evaluate(call3)
	// Because rm -rf / is present, it will hit catastrophic check and DENY
	if res3 == nil || res3.Decision != harness.DecisionDeny {
		t.Errorf("expected DENY for chained catastrophic, got %+v", res3)
	}
}

func TestFastPath_MutatingPassThrough(t *testing.T) {
	filter := NewDefaultFilter()

	call := &harness.NormalizedToolCall{
		ToolName: "run_command",
		Command:  "npm install express",
	}
	res := filter.Evaluate(call)
	if res != nil {
		t.Errorf("expected nil (pass-through to semantic evaluator), got %+v", res)
	}
}
