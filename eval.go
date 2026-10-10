package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"jev-guard/pkg/config"
	"jev-guard/pkg/harness"
)

type evalOptions struct {
	cmd, tool, target, payloadFile, cwd string
	offline, explain, asJSON            bool
}

// evalReport is the machine-readable result of `jev-guard eval --json`.
type evalReport struct {
	Decision         string   `json:"decision,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	Source           string   `json:"source,omitempty"`
	Confidence       float64  `json:"confidence,omitempty"`
	WouldSendToJudge bool     `json:"would_send_to_typesafe"`
	Offline          bool     `json:"offline"`
	Mode             string   `json:"mode"`
	Diagnostics      []string `json:"config_diagnostics,omitempty"`
	Harness          string   `json:"harness"`
	ToolName         string   `json:"tool_name"`
	Command          string   `json:"command,omitempty"`
	TargetPath       string   `json:"target_path,omitempty"`
	Cwd              string   `json:"cwd,omitempty"`
	WorkspaceRoots   []string `json:"workspace_roots,omitempty"`
	Contained        bool     `json:"boundary_contained"`
	FastpathRan      bool     `json:"fastpath_ran"`
	FastpathDecision string   `json:"fastpath_decision,omitempty"`
	FastpathReason   string   `json:"fastpath_reason,omitempty"`
	TypeSafeRan      bool     `json:"typesafe_ran"`
	Judgments        any      `json:"typesafe_judgments,omitempty"`
	TypeSafeError    string   `json:"typesafe_error,omitempty"`
	HarnessOutput    string   `json:"harness_output,omitempty"`
	HookExitCode     *int     `json:"hook_exit_code,omitempty"`
}

var errEvalUsage = errors.New("usage error")

func parseEvalArgs(args []string) (*evalOptions, error) {
	o := &evalOptions{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := strings.Cut(a, "=")
		str := func() (string, error) {
			if hasVal {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%w: flag %s requires a value", errEvalUsage, name)
			}
			i++
			return args[i], nil
		}
		var err error
		switch name {
		case "--cmd":
			o.cmd, err = str()
		case "--tool":
			o.tool, err = str()
		case "--target":
			o.target, err = str()
		case "--payload":
			o.payloadFile, err = str()
		case "--cwd":
			o.cwd, err = str()
		case "--offline":
			o.offline = true
		case "--explain":
			o.explain = true
		case "--json":
			o.asJSON = true
		default:
			return nil, fmt.Errorf("%w: unrecognized argument %s", errEvalUsage, a)
		}
		if err != nil {
			return nil, err
		}
	}
	modes := 0
	if o.cmd != "" {
		modes++
	}
	if o.tool != "" || o.target != "" {
		modes++
		if o.tool == "" || o.target == "" {
			return nil, fmt.Errorf("%w: --tool and --target must be used together", errEvalUsage)
		}
	}
	if o.payloadFile != "" {
		modes++
	}
	if modes != 1 {
		return nil, fmt.Errorf("%w: specify exactly one of --cmd, --tool with --target, or --payload", errEvalUsage)
	}
	return o, nil
}

func synthesizePayload(o *evalOptions, cwd string) ([]byte, error) {
	payload := map[string]interface{}{"cwd": cwd}
	if o.cmd != "" {
		payload["tool_name"] = "Bash"
		payload["tool_input"] = map[string]interface{}{"command": o.cmd}
	} else {
		key := "file_path"
		switch strings.ToLower(o.tool) {
		case "glob", "grep", "ls":
			key = "path"
		}
		payload["tool_name"] = o.tool
		payload["tool_input"] = map[string]interface{}{key: o.target}
	}
	return json.Marshal(payload)
}

// runEval implements `jev-guard eval`. It never writes session state or audit entries.
// It returns 0 whenever evaluation succeeded (regardless of decision) and 2 on usage errors.
func runEval(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, err := parseEvalArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "jev-guard eval: %v\n", err)
		fmt.Fprintln(stderr, "Usage: jev-guard eval (--cmd CMD | --tool NAME --target PATH | --payload FILE) [--cwd DIR] [--offline] [--explain] [--json]")
		return 2
	}

	var raw []byte
	if o.payloadFile != "" {
		if o.payloadFile == "-" {
			raw, err = io.ReadAll(stdin)
		} else {
			raw, err = os.ReadFile(o.payloadFile)
		}
		if err != nil {
			fmt.Fprintf(stderr, "jev-guard eval: cannot read payload: %v\n", err)
			return 2
		}
	} else {
		cwd := o.cwd
		if cwd == "" {
			cwd, _ = os.Getwd()
		}
		if raw, err = synthesizePayload(o, cwd); err != nil {
			fmt.Fprintf(stderr, "jev-guard eval: %v\n", err)
			return 2
		}
	}

	call, err := harness.ParsePayload(raw)
	if err != nil {
		fmt.Fprintf(stderr, "jev-guard eval: invalid payload: %v\n", err)
		return 2
	}
	if o.cwd != "" && o.payloadFile != "" {
		call.Cwd = o.cwd
	}

	cfg := config.LoadConfigForCall(call)
	trace := traceGateEvaluation(call, cfg, o.offline)
	rep := buildEvalReport(call, cfg, trace, o.offline)

	switch {
	case o.asJSON:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	case o.explain:
		printExplain(stdout, call, cfg, trace, rep)
	default:
		fmt.Fprintln(stdout, summaryLine(rep))
	}
	return 0
}

func buildEvalReport(call *harness.NormalizedToolCall, cfg *config.Config, t *gateTrace, offline bool) *evalReport {
	rep := &evalReport{
		Offline:          offline,
		Mode:             cfg.Mode,
		Diagnostics:      cfg.Diagnostics,
		Harness:          string(call.Harness),
		ToolName:         call.ToolName,
		Command:          call.Command,
		TargetPath:       call.TargetPath,
		Cwd:              call.Cwd,
		WorkspaceRoots:   call.WorkspaceRoots,
		Contained:        t.Contained,
		FastpathRan:      t.FastpathRan,
		TypeSafeRan:      t.SemanticRan,
		WouldSendToJudge: t.WouldSendToJudge,
	}
	if t.Judgments != nil {
		rep.Judgments = t.Judgments
	}
	if t.Fastpath != nil {
		rep.FastpathDecision = string(t.Fastpath.Decision)
		rep.FastpathReason = t.Fastpath.Reason
	}
	if t.EvalErr != nil {
		rep.TypeSafeError = t.EvalErr.Error()
	}
	if t.Final != nil {
		rep.Decision = string(t.Final.Decision)
		rep.Reason = t.Final.Reason
		rep.Source = t.Final.Source
		rep.Confidence = t.Final.Confidence
		if code, out, err := harness.FormatResponseForCall(call, *t.Final); err == nil {
			rep.HarnessOutput = string(out)
			rep.HookExitCode = &code
		}
	}
	return rep
}

func summaryLine(rep *evalReport) string {
	if rep.Decision == "" {
		return "no fastpath verdict: would be sent to TypeSafe (skipped, --offline)"
	}
	return fmt.Sprintf("%s: %s (source: %s)", strings.ToUpper(rep.Decision), rep.Reason, rep.Source)
}

func printExplain(w io.Writer, call *harness.NormalizedToolCall, cfg *config.Config, t *gateTrace, rep *evalReport) {
	fmt.Fprintln(w, "[1] Config")
	fmt.Fprintf(w, "    user config: %s\n", cfg.UserConfigPath)
	fmt.Fprintf(w, "    mode:        %s (%s)\n", cfg.Mode, cfg.Sources["mode"])
	fmt.Fprintf(w, "    fastpath:    %t\n", cfg.IsFastpathEnabled())
	for _, d := range cfg.Diagnostics {
		fmt.Fprintf(w, "    note:        %s\n", d)
	}
	fmt.Fprintln(w, "[2] Normalized tool call")
	fmt.Fprintf(w, "    harness: %s\n    tool:    %s\n    command: %s\n    target:  %s\n    cwd:     %s\n",
		call.Harness, call.ToolName, call.Command, call.TargetPath, call.Cwd)
	if len(call.WorkspaceRoots) > 0 {
		fmt.Fprintf(w, "    roots:   %s\n", strings.Join(call.WorkspaceRoots, ", "))
	}
	fmt.Fprintln(w, "[3] Boundary")
	switch {
	case strings.TrimSpace(call.TargetPath) == "":
		fmt.Fprintln(w, "    no target path: treated as contained")
	case t.Contained:
		fmt.Fprintln(w, "    target is inside the workspace")
	default:
		fmt.Fprintln(w, "    target is OUTSIDE the workspace (or could not be resolved)")
	}
	fmt.Fprintln(w, "[4] Fastpath")
	switch {
	case !t.FastpathRan:
		fmt.Fprintln(w, "    disabled")
	case t.Fastpath != nil:
		fmt.Fprintf(w, "    verdict: %s - %s\n", t.Fastpath.Decision, t.Fastpath.Reason)
	default:
		fmt.Fprintln(w, "    no verdict (falls through to TypeSafe)")
	}
	fmt.Fprintln(w, "[5] TypeSafe")
	switch {
	case t.SemanticRan && t.EvalErr != nil:
		fmt.Fprintf(w, "    error: %v\n", t.EvalErr)
	case t.SemanticRan && t.Judgments != nil:
		b, _ := json.MarshalIndent(t.Judgments, "    ", "  ")
		fmt.Fprintf(w, "    judgments: %s\n", b)
	case t.WouldSendToJudge:
		fmt.Fprintln(w, "    would be sent to TypeSafe (skipped, --offline)")
	default:
		fmt.Fprintln(w, "    not consulted (fastpath decided)")
	}
	fmt.Fprintln(w, "[6] Decision")
	if rep.Decision == "" {
		fmt.Fprintln(w, "    none (undetermined offline)")
	} else {
		fmt.Fprintf(w, "    %s: %s (source: %s)\n", strings.ToUpper(rep.Decision), rep.Reason, rep.Source)
	}
	fmt.Fprintln(w, "[7] Harness output")
	if rep.HookExitCode == nil {
		fmt.Fprintln(w, "    n/a")
		fmt.Fprintln(w, "[8] Hook exit code")
		fmt.Fprintln(w, "    n/a")
		return
	}
	fmt.Fprintf(w, "    %s\n", rep.HarnessOutput)
	fmt.Fprintln(w, "[8] Hook exit code")
	fmt.Fprintf(w, "    %d\n", *rep.HookExitCode)
}
