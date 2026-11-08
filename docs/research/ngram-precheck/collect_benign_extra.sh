#!/usr/bin/env bash
# Top-up of the benign corpus: docs pages (CONTRIBUTING/SECURITY/AGENTS/CLAUDE/docs/*.md) from public repos via gh api,
# and MCP-filesystem-style read_file results wrapping local source files. Read-only on the sources.
set -u
OUT=$1
mkdir -p "$OUT"/{gh_docs_pages,mcp_fs_read}
save() { cat > "$(mktemp "$OUT/$1/XXXXXXXX.txt")"; }
raw() { gh api -H 'Accept: application/vnd.github.raw' "repos/$1/contents/$2" 2>/dev/null | head -c 30000; }
for r in golang/go cli/cli kubernetes/kubernetes nodejs/node python/cpython microsoft/vscode facebook/react \
         vercel/next.js hashicorp/terraform astral-sh/uv BurntSushi/ripgrep neovim/neovim django/django pallets/flask \
         anthropics/claude-code modelcontextprotocol/servers openai/codex openai/openai-python denoland/deno rust-lang/rust; do
  for p in CONTRIBUTING.md SECURITY.md AGENTS.md CLAUDE.md .github/CONTRIBUTING.md .github/SECURITY.md; do
    raw "$r" "$p" | { s=$(cat); [ ${#s} -gt 300 ] && [ "${s:0:1}" != "{" ] && printf %s "$s" | save gh_docs_pages; }
  done
done
# MCP filesystem server style: {"content":[{"type":"text","text": <file>}]}
find "$(go env GOROOT)/src/net/http" "$(go env GOROOT)/src/os" -maxdepth 1 -name '*.go' ! -name '*_test.go' -size +2k 2>/dev/null \
  | sort | head -40 | while read -r f; do
  head -c 12000 "$f" | python3 -I -c 'import json,sys; print(json.dumps({"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":sys.stdin.read()}]}}))' | save mcp_fs_read
done
find "$OUT/gh_docs_pages" "$OUT/mcp_fs_read" -type f -size -100c -delete
for d in "$OUT"/*/; do echo "$(ls "$d" | wc -l) $(basename "$d")"; done
