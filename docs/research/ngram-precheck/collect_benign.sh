#!/usr/bin/env bash
# Collects ~550 real benign "tool outputs" into $1/<category>/NNN.txt. Read-only on the sources.
set -u
OUT=$1
REPO=$2   # jev-guard checkout; set EXTRA_DOCS_DIR to scan another directory of local projects
mkdir -p "$OUT"/{readme_npm,doc_usr_share,man,repo_docs,gh_json,gh_readme_security,go_doc_mcp}
n=0
save() { cat > "$(mktemp "$OUT/$1/XXXXXXXX.txt")"; }

# 1. npm package READMEs from the local npx cache, plus Go toolchain READMEs
[ -n "${SKIP_NPM:-}" ] || for f in $HOME/.npm/_npx/*/node_modules/*/README.md $HOME/.npm/_npx/*/node_modules/@*/*/README.md \
         $(go env GOROOT)/src/*/README* $(go env GOROOT)/src/*/*/README* $(go env GOROOT)/README.md; do
  [ -f "$f" ] && [ $(stat -c %s "$f") -gt 500 ] && save readme_npm < "$f"
done

# 2. /usr/share/doc plain-text READMEs / changelogs (not compressed)
timeout 60 find /usr/share/doc -maxdepth 3 -type f \( -iname 'README*' -o -iname 'NEWS*' -o -iname '*.md' \) ! -name '*.gz' -size +500c 2>/dev/null \
  | head -70 | while read -r f; do save doc_usr_share < "$f"; done

# 3. man pages rendered as a terminal tool would show them
for c in ls grep find git curl ssh tar rsync sed awk bash chmod chown cp mv rm ps top kill systemctl journalctl \
         docker make gcc python3 sudo apt dpkg ip ss crontab less man gpg openssl ln du df mount umount xargs sort \
         uniq head tail cut tr wc diff patch env printenv nano tmux zip unzip wget scp jq; do
  MANWIDTH=100 man -P cat "$c" 2>/dev/null | col -b | head -c 20000 | { s=$(cat); [ ${#s} -gt 500 ] && printf %s "$s" | save man; }
done

# 4. Markdown docs in local projects (agent instruction files included: AGENTS.md / CLAUDE.md / SKILL.md)
timeout 60 find "$REPO" ${EXTRA_DOCS_DIR:-} -maxdepth 3 -iname '*.md' -not -path '*/node_modules/*' -not -path '*/.git/*' -size +300c 2>/dev/null \
  | sort -u | head -60 | while read -r f; do save repo_docs < "$f"; done

# 5. gh api JSON results for public repos (what an agent sees from `gh api` / a GitHub MCP server)
REPOS="golang/go cli/cli kubernetes/kubernetes rust-lang/rust nodejs/node python/cpython microsoft/vscode
facebook/react vercel/next.js denoland/deno hashicorp/terraform docker/compose torvalds/linux
sharkdp/fd BurntSushi/ripgrep junegunn/fzf jqlang/jq neovim/neovim tmux/tmux astral-sh/uv
anthropics/claude-code modelcontextprotocol/servers openai/openai-python pallets/flask django/django"
for r in $REPOS; do
  gh api "repos/$r" 2>/dev/null | save gh_json
  gh api "repos/$r/issues?per_page=3&state=all" 2>/dev/null | head -c 30000 | save gh_json
  gh api "repos/$r/pulls?per_page=2&state=closed" 2>/dev/null | head -c 30000 | save gh_json
  gh api "repos/$r/releases?per_page=1" 2>/dev/null | head -c 30000 | save gh_json
  gh api "repos/$r/commits?per_page=3" 2>/dev/null | head -c 30000 | save gh_json
  gh api -H 'Accept: application/vnd.github.raw' "repos/$r/readme" 2>/dev/null | head -c 30000 | save gh_json
done

# 6. Security/LLM-safety READMEs: benign text that discusses prompt injection (hard negatives)
for r in protectai/llm-guard NVIDIA/garak leondz/garak OWASP/www-project-top-10-for-large-language-model-applications \
         protectai/rebuff greshake/llm-security microsoft/BIPIA ethz-spylab/agentdojo lakeraai/pint-benchmark \
         meta-llama/PurpleLlama NVIDIA/NeMo-Guardrails guardrails-ai/guardrails promptfoo/promptfoo \
         Azure/PyRIT tldrsec/prompt-injection-defenses jthack/PIPE; do
  gh api -H 'Accept: application/vnd.github.raw' "repos/$r/readme" 2>/dev/null | head -c 30000 \
    | { s=$(cat); [ ${#s} -gt 300 ] && printf %s "$s" | save gh_readme_security; }
  gh api "repos/$r/issues?per_page=2&state=all" 2>/dev/null | head -c 30000 \
    | { s=$(cat); [ ${#s} -gt 300 ] && printf %s "$s" | save gh_readme_security; }
done

# 7. `go doc` output wrapped as an MCP tools/call result
for p in fmt os os/exec net/http encoding/json io strings bytes bufio context sync time path/filepath regexp \
         crypto/sha256 crypto/tls database/sql flag log log/slog errors sort strconv testing text/template \
         html/template embed archive/tar compress/gzip net/url mime/multipart runtime reflect unicode/utf8 \
         math/rand os/signal syscall io/fs net crypto/rand hash/crc32 container/heap go/ast; do
  go doc -all "$p" 2>/dev/null | head -c 12000 \
    | python3 -I -c 'import json,sys; print(json.dumps({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":sys.stdin.read()}],"isError":False}}))' \
    | save go_doc_mcp
done
find "$OUT" -type f -size -100c -delete
for d in "$OUT"/*/; do echo "$(ls "$d" | wc -l) $(basename "$d")"; done
