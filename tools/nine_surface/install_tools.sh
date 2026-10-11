#!/usr/bin/env bash
# Install the third-party tools of the nine-surface benchmark at the versions and
# commits the committed results were produced with, each under TOOL_ROOT.
#
#   bash tools/nine_surface/install_tools.sh /path/to/tool-root
#
# This downloads and installs third-party code and its dependencies: review the
# pins first and run it on a disposable machine. It installs nothing into this
# repository's environment. Needs: git, gcc, Go 1.24+ (GOTOOLCHAIN=auto fetches
# newer toolchains for numbat and vet), uv, Python 3.13.
set -euo pipefail

root="${1:?usage: install_tools.sh TOOL_ROOT}"
mkdir -p "$root/third_party" "$root/venvs" "$root/bin" "$root/share"
root="$(cd "$root" && pwd)"

venv() {  # name package==version
  uv venv --quiet --allow-existing -p 3.13 "$root/venvs/$1"
  uv pip install --quiet --python "$root/venvs/$1/bin/python" "$2"
}

checkout() {  # owner/repo sha
  local dir="$root/third_party/${1/\//_}"
  if [[ ! -d "$dir/.git" ]]; then
    git clone --quiet "https://github.com/$1" "$dir"
  fi
  git -C "$dir" fetch --quiet --depth 1 origin "$2" 2>/dev/null || true
  git -C "$dir" -c advice.detachedHead=false checkout --quiet "$2"
  echo "$dir"
}

# Python tools (PyPI)
venv snyk-agent-scan "snyk-agent-scan==0.6.8"
venv mcp-scanner "cisco-ai-mcp-scanner==4.8.6"
venv agentmesh-discovery "agentmesh-discovery==5.0.0"
venv agentdiscover "agentdiscover==2.9.5"

# Go tools
numbat=$(checkout perplexityai/numbat 77ece3a76dce24f44a00128d7a3c9c743c0e64fa)
(cd "$numbat" && CGO_ENABLED=0 GOTOOLCHAIN=auto GOFLAGS=-mod=mod go build -trimpath -o "$root/bin/numbat" ./cmd/numbat)

CGO_ENABLED=1 GOBIN="$root/bin" GOTOOLCHAIN=auto GOFLAGS=-mod=mod go install github.com/safedep/vet@v1.20.0

aig=$(checkout Tencent/AI-Infra-Guard d9f3aa481ba10c5c00f37f24d361f4ddb944b065)
(cd "$aig" && CGO_ENABLED=0 GOFLAGS=-mod=mod go build -ldflags="-s -w" -trimpath -buildvcs=false \
  -o "$root/bin/ai-infra-guard" ./cmd/cli/main.go)
mkdir -p "$root/share/ai-infra-guard"
cp -r "$aig/data/fingerprints" "$aig/data/vuln" "$aig/data/vuln_en" "$root/share/ai-infra-guard/"

# Fleet's ai_tools table (MIT), compiled into a small program that prints its rows as JSON.
fleet="$root/third_party/fleet-sparse"
if [[ ! -d "$fleet/.git" ]]; then
  git clone --quiet --filter=blob:none --no-checkout https://github.com/fleetdm/fleet "$fleet"
  git -C "$fleet" sparse-checkout set orbit/pkg/table/ai_tools
fi
git -C "$fleet" -c advice.detachedHead=false checkout --quiet cf1217bafcd5cdce367165b1c604f94ed559e3d0
mod="$root/third_party/fleet-ai-tools"
mkdir -p "$mod/cmd/fleet-ai-tools"
rm -rf "$mod/ai_tools" && cp -r "$fleet/orbit/pkg/table/ai_tools" "$mod/ai_tools"
find "$mod/ai_tools" -name '*_test.go' -delete
grep -rl 'github.com/fleetdm/fleet/v4/orbit/pkg/table/ai_tools' "$mod/ai_tools" \
  | xargs -r sed -i 's#github.com/fleetdm/fleet/v4/orbit/pkg/table/ai_tools#fleetaitools/ai_tools#g'
cat > "$mod/go.mod" <<'EOF_GOMOD'
module fleetaitools

go 1.24

require (
	github.com/osquery/osquery-go v0.0.0-20250131154556-629f995b6947
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/shirou/gopsutil/v4 v4.26.2
	golang.org/x/sys v0.47.0
)
EOF_GOMOD
cat > "$mod/cmd/fleet-ai-tools/main.go" <<'EOF_MAIN'
// fleet-ai-tools prints the rows of Fleet's ai_tools osquery table for the current HOME as JSON.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"fleetaitools/ai_tools"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {
	version := flag.Bool("version", false, "print the vendored commit and exit")
	types := flag.String("types", "", "comma-separated ai_tools types to keep (default all)")
	flag.Parse()
	if *version {
		fmt.Println("fleetdm/fleet cf1217bafcd5cdce367165b1c604f94ed559e3d0 orbit/pkg/table/ai_tools; upstream karmine05/agentic-detector v0.3.0")
		return
	}
	rows, err := ai_tools.Generate(context.Background(), table.QueryContext{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	self := fmt.Sprint(os.Getpid())
	keep := map[string]bool{}
	for _, t := range strings.Split(*types, ",") {
		if t != "" {
			keep[t] = true
		}
	}
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		if r["pid"] == self || (len(keep) > 0 && !keep[r["type"]]) {
			continue
		}
		out = append(out, r)
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
EOF_MAIN
(cd "$mod" && GOFLAGS=-mod=mod go mod tidy >/dev/null 2>&1 && CGO_ENABLED=0 GOFLAGS=-mod=mod go build -trimpath -o "$root/bin/fleet-ai-tools" ./cmd/fleet-ai-tools)

cat > "$root/tools.json" <<EOF_JSON
{
 "tool_root": "$root",
 "tools": {
  "snyk-agent-scan": {"bin": "$root/venvs/snyk-agent-scan/bin/snyk-agent-scan", "version": "0.6.8"},
  "cisco-mcp-scanner": {"bin": "$root/venvs/mcp-scanner/bin/mcp-scanner", "version": "cisco-ai-mcp-scanner 4.8.6"},
  "agentmesh-discovery": {"bin": "$root/venvs/agentmesh-discovery/bin/agent-discovery", "version": "agentmesh-discovery 5.0.0"},
  "agentdiscover": {"bin": "$root/venvs/agentdiscover/bin/agentdiscover", "version": "2.9.5"},
  "numbat": {"bin": "$root/bin/numbat", "version": "dev+77ece3a76dce (2026-10-09)"},
  "vet": {"bin": "$root/bin/vet", "version": "v1.20.0"},
  "ai-infra-guard": {"bin": "$root/bin/ai-infra-guard", "version": "v4.6.5 (d9f3aa4)",
                     "fingerprints": "$root/share/ai-infra-guard/fingerprints", "vuln": "$root/share/ai-infra-guard/vuln_en"},
  "fleet-ai-tools": {"bin": "$root/bin/fleet-ai-tools", "version": "fleetdm/fleet cf1217b (2026-10-11) ai_tools"}
 }
}
EOF_JSON
echo "tools installed under $root; add a shadowscan entry (python interpreter and repo path) to $root/tools.json"
