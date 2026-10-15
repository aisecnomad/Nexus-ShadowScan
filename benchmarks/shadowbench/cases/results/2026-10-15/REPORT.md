# ShadowBench expanded corpus: 450 cases, 17 tools

**Corpus date**: 2026-10-15  
**Seed**: 20261015  
**Stream scheme**: sha256  
**Per surface**: 50

> **This report is a coverage analysis, not a measured evaluation.** The eight
> new tool adapters were written in this session. None of the eight new tools
> are installed, so the harness has not run them: no precision, recall, F1 or
> any other measured metric is reported for them. The coverage numbers below
> show how many of the benchmark's 450 cases and 1,162 entities each tool
> *declares it can handle* based on its adapter's surface and modality
> registrations. Measured results require installing each tool and running the
> harness (`python -m tools.shadowbench.cases run`).
>
> The nine original tools' results from the 2026-10-11 run (346-case corpus)
> remain the only measured evaluation. Those results are in
> [`../2026-10-11/REPORT.md`](../2026-10-11/REPORT.md).
>
> This benchmark is not independent. See the cases README's Bias and limits
> section and [AGENTS.md](../../../../../AGENTS.md).

## Corpus summary

| Surface | Modality | Cases | Entities | Decoys |
|---------|----------|------:|--------:|---------:|
| code | checkout | 50 | 362 | 0 |
| identity | okta-export | 25 | 57 | 103 |
| identity | entra-export | 25 | 60 | 102 |
| gateway | litellm-export | 25 | 84 | 0 |
| gateway | bedrock-export | 25 | 78 | 0 |
| lowcode | powerplatform-export | 25 | 50 | 70 |
| lowcode | n8n-export | 25 | 46 | 81 |
| saas | slack-export | 25 | 64 | 82 |
| saas | github-export | 25 | 51 | 81 |
| cloud | aws-export | 25 | 50 | 68 |
| cloud | k8s-export | 25 | 52 | 94 |
| endpoint | home | 50 | 31 | 0 |
| network | passive | 25 | 15 | 0 |
| network | active | 25 | 36 | 60 |
| runtime | snapshot | 25 | 71 | 122 |
| runtime | live | 25 | 55 | 112 |
| **Total** | | **450** | **1,162** | **975** |

Changes from the 346-case corpus (2026-10-11):

- **Per-surface increase**: 40 → 50 cases per surface (25 per modality for
  two-modality surfaces, 50 for single-modality surfaces)
- **Code repos expanded**: 26 → 50 repositories (31 positive, 8 control,
  11 near-miss), adding `aisecnomad/Nexus-ShadowScan` and 23 other repos
  from the discovery benchmark corpus
- **New seed**: 20261015 (sha256 stream scheme, so the seed controls the
  cases unlike the legacy 2026-10-11 corpus)

## Tool coverage

17 tools, 9 original + 8 new. Only the 9 original have measured results from
the 2026-10-11 run; the 8 new tools have adapters but have not been run.

| Tool | Surfaces | Cases | Entities | Status |
|------|-------:|------:|---------:|--------|
| ShadowScan | 9/9 | 425/450 (94.4%) | 1,126/1,162 (96.9%) | measured (2026-10-11) |
| AgentDiscover | 2/9 | 100/450 (22.2%) | 393/1,162 (33.8%) | measured (2026-10-11) |
| Agent Governance Toolkit | 3/9 | 125/450 (27.8%) | 448/1,162 (38.6%) | measured (2026-10-11) |
| SafeDep vet | 2/9 | 100/450 (22.2%) | 393/1,162 (33.8%) | measured (2026-10-11) |
| AI-Infra-Guard | 1/9 | 25/450 (5.6%) | 36/1,162 (3.1%) | measured (2026-10-11) |
| Cisco MCP Scanner | 1/9 | 50/450 (11.1%) | 31/1,162 (2.7%) | measured (2026-10-11) |
| Fleet ai_tools | 2/9 | 75/450 (16.7%) | 86/1,162 (7.4%) | measured (2026-10-11) |
| numbat | 1/9 | 50/450 (11.1%) | 31/1,162 (2.7%) | measured (2026-10-11) |
| Snyk Agent Scan | 1/9 | 50/450 (11.1%) | 31/1,162 (2.7%) | measured (2026-10-11) |
| **BBOT** | **1/9** | **25/450 (5.6%)** | **36/1,162 (3.1%)** | **adapter only** |
| **Bifrost** | **1/9** | **50/450 (11.1%)** | **162/1,162 (13.9%)** | **adapter only** |
| **MCPProxy** | **2/9** | **75/450 (16.7%)** | **67/1,162 (5.8%)** | **adapter only** |
| **Open Shadow AI** | **1/9** | **50/450 (11.1%)** | **115/1,162 (9.9%)** | **adapter only** |
| **osquery AI** | **1/9** | **25/450 (5.6%)** | **71/1,162 (6.1%)** | **adapter only** |
| **Provenza** | **1/9** | **50/450 (11.1%)** | **102/1,162 (8.8%)** | **adapter only** |
| **Shadow AI Detection Framework** | **1/9** | **50/450 (11.1%)** | **117/1,162 (10.1%)** | **adapter only** |
| **shadow-ai-detector** | **1/9** | **50/450 (11.1%)** | **362/1,162 (31.2%)** | **adapter only** |

### Surface coverage heatmap

```
                         cod  ide  ide  gat  gat  low  low  saa  saa  clo  clo  end  net  net  run  run
                         chk  okt  ent  lit  bed  pow  n8n  slk  git  aws  k8s  hom  pas  act  snp  liv
shadowscan                X    X    X    X    X    X    X    X    X    X    X    X    X    .    X    X
agentdiscover             X    .    .    .    .    .    .    .    .    .    .    X    .    .    .    .
agentmesh-discovery       X    .    .    .    .    .    .    .    .    .    .    X    .    .    .    X
vet                       X    .    .    .    .    .    .    .    .    .    .    X    .    .    .    .
shadow-ai-detector        X    .    .    .    .    .    .    .    .    .    .    .    .    .    .    .
shadow-ai-detect          .    X    X    .    .    .    .    .    .    .    .    .    .    .    .    .
bifrost                   .    .    .    X    X    .    .    .    .    .    .    .    .    .    .    .
openshadowai              .    .    .    .    .    .    .    X    X    .    .    .    .    .    .    .
provenza                  .    .    .    .    .    .    .    .    .    X    X    .    .    .    .    .
cisco-mcp-scanner         .    .    .    .    .    .    .    .    .    .    .    X    .    .    .    .
numbat                    .    .    .    .    .    .    .    .    .    .    .    X    .    .    .    .
snyk-agent-scan           .    .    .    .    .    .    .    .    .    .    .    X    .    .    .    .
mcpproxy                  .    .    .    .    .    .    .    .    .    .    .    X    .    X    .    .
fleet-ai-tools            .    .    .    .    .    .    .    .    .    .    .    X    .    .    .    X
ai-infra-guard            .    .    .    .    .    .    .    .    .    .    .    .    .    X    .    .
bbot                      .    .    .    .    .    .    .    .    .    .    .    .    .    X    .    .
osquery-ai                .    .    .    .    .    .    .    .    .    .    .    .    .    .    X    .
```

### Key observations

1. **ShadowScan covers 15 of 16 modalities** (94.4% of cases). The only gap
   is `network/active` (live service scanning). No other tool covers more
   than 3 surfaces.

2. **Most tools are single-surface.** 10 of the 17 tools cover only one
   surface. Only ShadowScan, Agent Governance Toolkit (3), AgentDiscover (2),
   vet (2), Fleet ai_tools (2) and MCPProxy (2) span multiple surfaces.

3. **The endpoint/home surface is the most competed**, with 7 tools covering
   it: ShadowScan, AgentDiscover, Agent Governance Toolkit, vet, Cisco MCP
   Scanner, numbat, Snyk Agent Scan and MCPProxy.

4. **Five surfaces have only 1-2 tools each**: lowcode (ShadowScan only),
   network/passive (ShadowScan only), gateway (ShadowScan + Bifrost),
   cloud (ShadowScan + Provenza), runtime/snapshot (ShadowScan + osquery).

5. **The code surface has 4 tools**: ShadowScan, AgentDiscover, vet, and
   shadow-ai-detector. Code is the only surface with public, real-world
   ground truth (50 pinned repositories).

## Reproducing this corpus

```bash
python -c "
import sys; sys.path.insert(0, '.')
from tools.shadowbench.cases.generate import main
main(['--seed', '20261015', '--per-surface', '50', '--output', 'benchmarks/shadowbench/cases/corpus-450.json'])
"
```

The generator digest, seed and stream scheme are recorded in the corpus
header. `verify` confirms they still produce the same cases.

## Running measured evaluation

To produce measured precision/recall/F1 results:

1. Install each tool at the version its adapter documents
2. Configure `tools.json` with each tool's binary path
3. Run: `python -m tools.shadowbench.cases run --corpus benchmarks/shadowbench/cases/corpus-450.json`
4. Score: `python -m tools.shadowbench.cases score`
5. Report: `python -m tools.shadowbench.cases report`

This requires a disposable machine with no credentials, network namespaces
(for active network cases) and PID namespaces (for live runtime cases). See
the [harness README](../../../../tools/shadowbench/cases/README.md).
