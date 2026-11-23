package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"jev-guard/pkg/harness"
)

func TestReadStandardInputAtLimit(t *testing.T) {
	data, err := readStandardInput(strings.NewReader(strings.Repeat(" ", maxHookInput)))
	if err != nil || len(data) != maxHookInput {
		t.Fatalf("read %d bytes, err = %v", len(data), err)
	}
}

func TestRunGateHoldsOnFailures(t *testing.T) {
	const antigravityInput = `{"toolCall":{"name":"view_file","args":{}}}`
	const claudeInput = `{"tool_name":"Read","tool_input":{}}`

	for _, tc := range []struct {
		name, input, reason string
		protocol            harness.HarnessType
		initialize          func() error
		deadline            time.Duration
	}{
		{
			name: "oversized Antigravity input", input: strings.Repeat(" ", maxHookInput+1),
			reason: "hook payload exceeds", protocol: harness.HarnessAntigravity,
		},
		{
			name: "invalid Antigravity input", input: "{",
			reason: "Failed to parse", protocol: harness.HarnessAntigravity,
		},
		{
			name: "panic in Antigravity evaluation", input: antigravityInput,
			reason: hookInternalError, protocol: harness.HarnessAntigravity,
			initialize: func() error { panic("internal detail") },
		},
		{
			name: "panic in Claude evaluation", input: claudeInput,
			reason: hookInternalError, protocol: harness.HarnessUnknown,
			initialize: func() error { panic("internal detail") },
		},
		{
			name: "Antigravity deadline", input: antigravityInput,
			reason: "exceeded its evaluation deadline", protocol: harness.HarnessAntigravity,
			deadline: 30 * time.Millisecond,
		},
		{
			name: "Claude deadline", input: claudeInput,
			reason: "exceeded its evaluation deadline", protocol: harness.HarnessUnknown,
			deadline: 30 * time.Millisecond,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			initialize := tc.initialize
			if tc.deadline != 0 {
				deadlineCtx, cancel := context.WithTimeout(ctx, tc.deadline)
				defer cancel()
				ctx = deadlineCtx
				release := make(chan struct{})
				defer close(release)
				initialize = func() error {
					<-release
					return errors.New("late initialization error")
				}
			} else if initialize == nil {
				initialize = func() error { return errors.New("invalid input reached config initialization") }
			}

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runGate(ctx, tc.protocol, initialize, hookStreams{strings.NewReader(tc.input), &stdout, &stderr})
			if tc.protocol == harness.HarnessAntigravity {
				var verdict struct {
					Decision, Reason string
				}
				err := json.Unmarshal(stdout.Bytes(), &verdict)
				if code != 0 || err != nil || verdict.Decision != "force_ask" || !strings.Contains(verdict.Reason, tc.reason) {
					t.Fatalf("exit = %d, verdict = %q, err = %v", code, stdout.String(), err)
				}
				return
			}
			if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.reason) {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunGateRecoversPanicDuringReplyDelivery(t *testing.T) {
	for _, protocol := range []harness.HarnessType{harness.HarnessAntigravity, harness.HarnessUnknown} {
		var output bytes.Buffer
		sink := &panicOnceWriter{Writer: &output}
		code := runGate(context.Background(), protocol, func() error { return nil }, hookStreams{
			input: strings.NewReader("{"), output: sink, stderr: sink,
		})
		want := 2
		if protocol == harness.HarnessAntigravity {
			want = 0
		}
		if code != want {
			t.Fatalf("%s exit = %d, want %d", protocol, code, want)
		}
		if !strings.Contains(output.String(), hookInternalError) {
			t.Fatalf("%s reply = %q, want internal error hold", protocol, output.String())
		}
	}
}

type panicOnceWriter struct {
	io.Writer
	panicked bool
}

func (w *panicOnceWriter) Write(data []byte) (int, error) {
	if !w.panicked {
		w.panicked = true
		panic("write failure")
	}
	return w.Writer.Write(data)
}
