package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/harness"
)

func TestReadStandardInputBound(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		wantError bool
	}{
		{"at limit", maxHookInput, false},
		{"above limit", maxHookInput + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := readStandardInput(strings.NewReader(strings.Repeat(" ", tc.size)))
			if tc.wantError {
				if err == nil || data != nil {
					t.Fatal("oversized input was accepted")
				}
			} else if err != nil || len(data) != tc.size {
				t.Fatalf("read %d bytes, err = %v", len(data), err)
			}
		})
	}
}

func TestAwaitHookReplyHoldsOnDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	release := make(chan struct{})
	defer close(release)

	reply := awaitHookReply(ctx, blockingHookReply, func() hookReply {
		<-release
		return hookReply{exitCode: 0, output: []byte("late verdict")}
	})
	if reply.exitCode != 2 || !strings.Contains(string(reply.output), "deadline") {
		t.Fatalf("got %+v, want a deadline hold", reply)
	}
}

func TestAwaitHookReplyHoldsOnPanic(t *testing.T) {
	reply := awaitHookReply(context.Background(), blockingHookReply, func() hookReply {
		panic("internal detail")
	})
	if reply.exitCode != 2 || string(reply.output) != "jev-guard hook encountered an internal error" {
		t.Fatalf("got %+v, want a generic internal error hold", reply)
	}
}

func blockingHookReply(reason string) hookReply {
	return formatHookReply(&harness.NormalizedToolCall{Harness: harness.HarnessClaudeCode}, harness.EvaluationResult{
		Decision: harness.DecisionAsk,
		Reason:   reason,
	})
}

func TestAntigravityHookHoldsOnInputError(t *testing.T) {
	input, err := os.CreateTemp(t.TempDir(), "hook-input")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := input.WriteString("{"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "hook-output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stdin, stdout := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = input, output
	defer func() { os.Stdin, os.Stdout = stdin, stdout }()

	if code := runGate(harness.HarnessAntigravity, func() error {
		t.Error("invalid input reached config initialization")
		return nil
	}); code != 0 {
		t.Fatalf("exit code = %d, want 0 with a JSON hold", code)
	}
	if _, err := output.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var verdict struct {
		Decision string
	}
	if err := json.NewDecoder(output).Decode(&verdict); err != nil || verdict.Decision != "force_ask" {
		t.Fatalf("decision = %q, err = %v, want force_ask", verdict.Decision, err)
	}
}
