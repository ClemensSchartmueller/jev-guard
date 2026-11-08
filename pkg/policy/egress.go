package policy

import (
	"path"
	"strings"

	"jev-guard/pkg/harness"
)

// outboundTools are tool names whose only purpose is a network request. Their
// arguments (URL, query string, prompt) can carry data off the machine.
var outboundTools = map[string]bool{
	"webfetch": true, "websearch": true, "read_url_content": true,
}

// shellTools carry a free-form command that IsEgressCall inspects.
var shellTools = map[string]bool{
	"bash": true, "powershell": true, "exec_command": true, "run_command": true,
}

// egressCommands are programs that send data to another host. Matching is on
// any command word (basename, lowercased, ".exe" stripped), not only the first,
// so wrappers such as `sudo curl` or `env X=1 wget` still count.
var egressCommands = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	"telnet": true, "ssh": true, "scp": true, "sftp": true, "ftp": true, "tftp": true,
	"rsync": true, "rclone": true, "http": true, "https": true, "xh": true, "aria2c": true,
	"mail": true, "mailx": true, "sendmail": true, "gh": true, "aws": true, "gsutil": true,
	"gcloud": true, "az": true, "s3cmd": true, "invoke-webrequest": true,
	"invoke-restmethod": true, "iwr": true, "irm": true, "bitsadmin": true,
	"send-mailmessage": true, "start-bitstransfer": true,
}

// egressSubcommands are subcommands that publish data to a remote. They match
// anywhere after their program, so `git -C repo push` still counts.
var egressSubcommands = map[string]string{
	"push": "git", "send-email": "git", "publish": "npm",
}

// egressMarkers are substrings that indicate a network endpoint or an inline
// network client (interpreter one-liners, PowerShell .NET clients, bash /dev/tcp).
var egressMarkers = []string{
	"://", "/dev/tcp/", "/dev/udp/", "net.webclient", "system.net.", "urllib", "requests.",
	"http.client", "socket", "fetch(", "net/http", "-urlcache",
}

// IsEgressCall reports whether a tool call can send data to another host. It is
// a deterministic, deliberately over-inclusive local heuristic: a false positive
// only turns an intent-authorized credential access into a confirmation prompt.
// It is not a complete exfiltration detector; an obfuscated command can evade it.
func IsEgressCall(call *harness.NormalizedToolCall) bool {
	if call == nil {
		return false
	}
	tool := strings.ToLower(call.ToolName)
	if outboundTools[tool] {
		return true
	}
	if !shellTools[tool] && strings.TrimSpace(call.Command) == "" {
		return false
	}
	return isEgressCommand(call.Command)
}

func isEgressCommand(command string) bool {
	cmd := strings.ToLower(command)
	for _, marker := range egressMarkers {
		if strings.Contains(cmd, marker) {
			return true
		}
	}
	words := strings.FieldsFunc(cmd, func(r rune) bool {
		return strings.ContainsRune(" \t\r\n;|&(){}<>`$\"'", r)
	})
	seen := map[string]bool{}
	for _, w := range words {
		w = strings.TrimSuffix(path.Base(strings.ReplaceAll(w, "\\", "/")), ".exe")
		if egressCommands[w] {
			return true
		}
		if program, ok := egressSubcommands[w]; ok && seen[program] {
			return true
		}
		seen[w] = true
	}
	return false
}
