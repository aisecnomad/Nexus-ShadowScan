#!/usr/bin/env bash
# Install the third-party tools of ShadowBench at the versions and
# commits the committed results were produced with, each under TOOL_ROOT.
#
#   bash tools/shadowbench/cases/install_tools.sh /path/to/tool-root
#
# Installs are version-pinned, not hash-locked. Each PyPI tool is pinned to
# one version but its transitive dependencies resolve at install time, with
# no hashes checked beyond what PyPI serves. The Go tools build from pinned
# commits with their own go.mod/go.sum (module checksums are verified against
# the Go checksum database); the Fleet wrapper module below has a hand-written
# go.mod with pinned direct requirements, and `go mod tidy` resolves the rest
# and writes its go.sum at install time. A rerun on another day can therefore
# install different transitive versions; record `uv pip freeze` per venv and
# the wrapper's go.sum next to any results.
#
# This downloads and installs third-party code and its dependencies: review the
# pins first and run it on a disposable machine. It installs nothing into this
# repository's environment. Needs: bash 4.4+, git, gcc, Go 1.24+
# (GOTOOLCHAIN=auto fetches newer toolchains for numbat and vet), uv, Python 3.13.
set -euo pipefail
shopt -s inherit_errexit  # a failing command inside $(checkout ...) stops the script too

root="${1:?usage: install_tools.sh TOOL_ROOT}"
mkdir -p "$root/third_party" "$root/venvs" "$root/bin" "$root/share"
root="$(cd "$root" && pwd)"

venv() {  # name package==version
  uv venv --quiet --allow-existing -p 3.13 "$root/venvs/$1"
  uv pip install --quiet --python "$root/venvs/$1/bin/python" "$2"
}

checkout() {  # owner/repo sha -> prints the checkout directory, detached at sha
  local dir="$root/third_party/${1/\//_}"
  if [[ ! -d "$dir/.git" ]]; then
    git -c core.hooksPath=/dev/null clone --quiet --no-checkout "https://github.com/$1" "$dir"
  fi
  if ! git -C "$dir" cat-file -e "$2^{commit}" 2>/dev/null; then  # absent locally: fetch it
    git -C "$dir" -c core.hooksPath=/dev/null fetch --quiet origin "$2"
  fi
  git -C "$dir" -c core.hooksPath=/dev/null -c advice.detachedHead=false \
    checkout --quiet --detach --no-recurse-submodules "$2"
  local head
  head="$(git -C "$dir" rev-parse HEAD)"
  if [[ "$head" != "$2" ]]; then
    echo "$1: HEAD $head is not the pinned commit $2" >&2
    exit 1
  fi
  echo "$dir"
}

# Python tools (PyPI)
venv snyk-agent-scan "snyk-agent-scan==0.6.8"
venv mcp-scanner "cisco-ai-mcp-scanner==4.8.6"
venv agentmesh-discovery "agentmesh-discovery==5.0.0"
venv agentdiscover "agentdiscover==2.9.5"

# Go tools: module-aware builds against each project's own go.mod and go.sum
# (the default -mod=readonly fails instead of rewriting them).
numbat=$(checkout perplexityai/numbat 77ece3a76dce24f44a00128d7a3c9c743c0e64fa)
(cd "$numbat" && CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath -o "$root/bin/numbat" ./cmd/numbat)

CGO_ENABLED=1 GOBIN="$root/bin" GOTOOLCHAIN=auto go install github.com/safedep/vet@v1.20.0

aig=$(checkout Tencent/AI-Infra-Guard d9f3aa481ba10c5c00f37f24d361f4ddb944b065)
(cd "$aig" && CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -buildvcs=false \
  -o "$root/bin/ai-infra-guard" ./cmd/cli/main.go)
mkdir -p "$root/share/ai-infra-guard"
cp -r "$aig/data/fingerprints" "$aig/data/vuln" "$aig/data/vuln_en" "$root/share/ai-infra-guard/"

# Fleet's ai_tools table (MIT), compiled into a small program that prints its rows as JSON.
fleet_commit=cf1217bafcd5cdce367165b1c604f94ed559e3d0
fleet_version="fleet ai_tools (fleetdm/fleet main $fleet_commit, 2026-10-11; upstream karmine05/agentic-detector v0.3.0 7c942d0)"
fleet="$root/third_party/fleet-sparse"
if [[ ! -d "$fleet/.git" ]]; then
  git -c core.hooksPath=/dev/null clone --quiet --filter=blob:none --no-checkout https://github.com/fleetdm/fleet "$fleet"
  git -C "$fleet" sparse-checkout set orbit/pkg/table/ai_tools
fi
if ! git -C "$fleet" cat-file -e "$fleet_commit^{commit}" 2>/dev/null; then
  git -C "$fleet" -c core.hooksPath=/dev/null fetch --quiet origin "$fleet_commit"
fi
git -C "$fleet" -c core.hooksPath=/dev/null -c advice.detachedHead=false \
  checkout --quiet --detach --no-recurse-submodules "$fleet_commit"
if [[ "$(git -C "$fleet" rev-parse HEAD)" != "$fleet_commit" ]]; then
  echo "fleetdm/fleet: HEAD is not the pinned commit $fleet_commit" >&2
  exit 1
fi
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
cat > "$mod/cmd/fleet-ai-tools/main.go" <<EOF_MAIN
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
		fmt.Println("$fleet_version")
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
# `go mod tidy` resolves the wrapper's indirect requirements from the pinned
# direct ones and writes go.sum; its errors stop the install. The build then
# runs with the default -mod=readonly against exactly that go.mod and go.sum.
(cd "$mod" && go mod tidy && CGO_ENABLED=0 go build -trimpath -o "$root/bin/fleet-ai-tools" ./cmd/fleet-ai-tools)

# Each entry's "version" is the version or commit pinned above, in the
# form the committed results manifest records
# (benchmarks/shadowbench/cases/results/2026-10-11/manifest.json). The
# runner records an entry's "version" in the run manifest as given, for
# every tool alike, instead of running the adapter's version probe
# (tool_version in runner.py). It is not checked against the binary:
# remove it from an entry to record what the installed tool reports.
cat > "$root/tools.json" <<EOF_JSON
{
 "tool_root": "$root",
 "tools": {
  "snyk-agent-scan": {"bin": "$root/venvs/snyk-agent-scan/bin/snyk-agent-scan", "version": "0.6.8"},
  "cisco-mcp-scanner": {"bin": "$root/venvs/mcp-scanner/bin/mcp-scanner", "version": "cisco-ai-mcp-scanner 4.8.6"},
  "agentmesh-discovery": {"bin": "$root/venvs/agentmesh-discovery/bin/agent-discovery", "version": "agentmesh-discovery 5.0.0"},
  "agentdiscover": {"bin": "$root/venvs/agentdiscover/bin/agentdiscover", "version": "2.9.5"},
  "numbat": {"bin": "$root/bin/numbat", "version": "dev+77ece3a76dce"},
  "vet": {"bin": "$root/bin/vet", "version": "v1.20.0"},
  "ai-infra-guard": {"bin": "$root/bin/ai-infra-guard", "version": "v4.6.5",
                     "fingerprints": "$root/share/ai-infra-guard/fingerprints", "vuln": "$root/share/ai-infra-guard/vuln_en"},
  "fleet-ai-tools": {"bin": "$root/bin/fleet-ai-tools", "version": "$fleet_version"}
 }
}
EOF_JSON
echo "tools installed under $root; add a shadowscan entry (python interpreter and repo path) to $root/tools.json"
