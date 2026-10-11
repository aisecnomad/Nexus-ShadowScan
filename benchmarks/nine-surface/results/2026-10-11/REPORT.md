# Nine-surface shadow AI agent discovery benchmark

Corpus: 346 cases on 9 surfaces carrying 738 expected entities and 735 decoys (SHA-256 `90638b8eea6a7a13e837163ccacb14af43ab67c81a175e476f41559570363b89`, generator `55b40eb49aaaa030470c0549d7e8a79be97a63ab86be2d02fffce34ef2710a7c`). Run started 2026-10-11T17:42:05+00:00 and finished 2026-10-11T17:50:27+00:00 on Linux-6.18.44-fc-v114-x86_64-with-glibc2.39 with 3 parallel workers; timings include contention.

Ground truth is generated from written rubrics with per-entity evidence (see the README). It is author-written and synthetic, not independent human review and not a sample of any real estate; the results describe how each tool behaves on these inputs, not field precision or recall.

## Headline

| Tool | Version | Surfaces | Estate recall | In-scope entity P / R / F1 | Specificity on decoys | Agent recall | Agent false alarms | Case-level balanced accuracy | Errors | Incomplete | Seconds median / p90 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | 0.1.2+b52539de280b | 9/9: cloud, code, endpoint, gateway, identity, lowcode, network, runtime, saas | 84% (622/738) | 78% / 88% / 83% (80–85) | 75% | 76% (269/356) | 16% (164/1035) | 80% | 0 | 27 | 2.0 / 2.7 |
| agentdiscover | 2.9.5 | 2/9: code, endpoint | 4% (26/738) | 10% / 20% / 13% (7–23) | n/a | 10% (8/83) | 0% (0/50) | 62% | 0 | 0 | 1.3 / 3.0 |
| ai-infra-guard | v4.6.5 | 1/9: network | 4% (26/738) | 100% / 81% / 90% (84–96) | 100% | 65% (11/17) | 17% (11/65) | 100% | 0 | 0 | 1.2 / 1.4 |
| vet | v1.20.0 | 2/9: code, endpoint | 2% (18/738) | 32% / 14% / 19% (11–28) | n/a | 22% (18/83) | 0% (0/50) | 57% | 0 | 0 | 0.2 / 0.2 |
| agentmesh-discovery | agentmesh-discovery 5.0.0 | 3/9: code, endpoint, runtime | 2% (15/738) | 83% / 8% / 15% (8–23) | 100% | 14% (15/108) | 0% (0/154) | 61% | 0 | 0 | 0.3 / 0.3 |
| fleet-ai-tools | fleet ai_tools (fleetdm/fleet main cf1217bafcd5cdce367165b1c604f94ed559e3d0, 2026-10-11; upstream karmine05/agentic-detector v0.3.0 7c942d0) | 2/9: endpoint, runtime | 2% (15/738) | 88% / 21% / 34% (20–48) | 100% | 26% (11/43) | 0% (0/110) | 64% | 0 | 0 | 0.0 / 0.0 |
| snyk-agent-scan | 0.6.8 | 1/9: endpoint | 1% (7/738) | 100% / 29% / 45% (21–65) | n/a | 39% (7/18) | 0% (0/6) | 65% | 0 | 0 | 1.0 / 1.1 |
| numbat | dev+77ece3a76dce | 1/9: endpoint | 0% (3/738) | 100% / 12% / 22% (0–44) | n/a | 17% (3/18) | 0% (0/6) | 56% | 0 | 0 | 0.0 / 0.0 |
| cisco-mcp-scanner | cisco-ai-mcp-scanner 4.8.6 | 1/9: endpoint | 0% (1/738) | 100% / 4% / 8% (0–25) | n/a | 6% (1/18) | 0% (0/6) | 52% | 0 | 0 | 4.4 / 4.9 |

Estate recall counts every expected entity in the corpus, charging a tool for the surfaces it does not cover. In-scope metrics count only the surfaces and modalities a tool ran on. Specificity is measured on decoy entities (records labeled none). Agent recall is the share of expected agents a tool reported as agents; agent false alarms are plain-AI entities and decoys it called agents. F1 intervals are 2,000-sample case bootstraps.

## By surface

### code (26 cases, 16 positive; 109 expected entities, 0 decoys; modalities checkout)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | checkout | 97% / 91% / 94% (90–96) | 99 / 3 / 10 / 0 | n/a | 95% | 0% | 100% / 100% | 0 | 7 | 2.7 |
| agentdiscover | checkout | 9% / 23% / 13% (7–25) | 25 / 247 / 84 / 0 | n/a | 11% | 0% | 62% / 90% | 0 | 0 | 1.6 |
| vet | checkout | 100% / 8% / 15% (6–26) | 9 / 0 / 100 / 0 | n/a | 14% | 0% | 38% / 100% | 0 | 0 | 0.1 |
| agentmesh-discovery | checkout | 83% / 5% / 9% (0–20) | 5 / 1 / 104 / 0 | n/a | 8% | 0% | 25% / 100% | 0 | 0 | 0.3 |

### identity (40 cases, 24 positive; 96 expected entities, 159 decoys; modalities entra-export, okta-export)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | entra-export, okta-export | 57% / 97% / 72% (63–79) | 93 / 69 / 3 / 90 | 57% | 47% | 23% | 100% / 0% | 0 | 0 | 1.9 |

| Tool | entra-export P / R / F1 | okta-export P / R / F1 |
|---|---|---|
| shadowscan | 59% / 93% / 72% | 56% / 100% / 72% |

### gateway (40 cases, 40 positive; 124 expected entities, 0 decoys; modalities bedrock-export, litellm-export)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | bedrock-export, litellm-export | 100% / 100% / 100% (100–100) | 124 / 0 / 0 / 0 | n/a | 100% | 0% | 100% / n/a | 0 | 0 | 2.8 |

| Tool | bedrock-export P / R / F1 | litellm-export P / R / F1 |
|---|---|---|
| shadowscan | 100% / 100% / 100% | 100% / 100% / 100% |

### lowcode (40 cases, 24 positive; 78 expected entities, 118 decoys; modalities n8n-export, powerplatform-export)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | n8n-export, powerplatform-export | 88% / 100% / 93% (87–98) | 78 / 11 / 0 / 107 | 91% | 100% | 27% | 100% / 75% | 0 | 0 | 1.9 |

| Tool | n8n-export P / R / F1 | powerplatform-export P / R / F1 |
|---|---|---|
| shadowscan | 100% / 100% / 100% | 79% / 100% / 88% |

### saas (40 cases, 24 positive; 88 expected entities, 110 decoys; modalities github-export, slack-export)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | github-export, slack-export | 51% / 88% / 64% (53–72) | 77 / 74 / 11 / 36 | 33% | 66% | 24% | 100% / 6% | 0 | 0 | 2.0 |

| Tool | github-export P / R / F1 | slack-export P / R / F1 |
|---|---|---|
| shadowscan | 57% / 72% / 64% | 48% / 100% / 65% |

### cloud (40 cases, 24 positive; 77 expected entities, 133 decoys; modalities aws-export, k8s-export)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | aws-export, k8s-export | 97% / 75% / 85% (78–90) | 58 / 2 / 19 / 131 | 98% | 41% | 11% | 96% / 94% | 0 | 0 | 1.8 |

| Tool | aws-export P / R / F1 | k8s-export P / R / F1 |
|---|---|---|
| shadowscan | 93% / 80% / 86% | 100% / 71% / 83% |

### endpoint (40 cases, 24 positive; 24 expected entities, 0 decoys; modalities home)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | home | 100% / 83% / 91% (80–98) | 20 / 0 / 4 / 0 | n/a | 94% | 0% | 83% / 100% | 0 | 0 | 1.9 |
| agentdiscover | home | 100% / 4% / 8% (0–25) | 1 / 0 / 23 / 0 | n/a | 6% | 0% | 4% / 100% | 0 | 0 | 1.2 |
| vet | home | 19% / 38% / 25% (13–37) | 9 / 39 / 15 / 0 | n/a | 50% | 0% | 100% / 0% | 0 | 0 | 0.2 |
| agentmesh-discovery | home | 67% / 17% / 27% (7–47) | 4 / 2 / 20 / 0 | n/a | 22% | 0% | 17% / 88% | 0 | 0 | 0.3 |
| fleet-ai-tools | home | 83% / 42% / 56% (34–74) | 10 / 2 / 14 / 0 | n/a | 33% | 0% | 42% / 88% | 0 | 0 | 0.0 |
| snyk-agent-scan | home | 100% / 29% / 45% (21–65) | 7 / 0 / 17 / 0 | n/a | 39% | 0% | 29% / 100% | 0 | 0 | 1.0 |
| numbat | home | 100% / 12% / 22% (0–44) | 3 / 0 / 21 / 0 | n/a | 17% | 0% | 12% / 100% | 0 | 0 | 0.0 |
| cisco-mcp-scanner | home | 100% / 4% / 8% (0–25) | 1 / 0 / 23 / 0 | n/a | 6% | 0% | 4% / 100% | 0 | 0 | 4.4 |

### network (40 cases, 24 positive; 44 expected entities, 50 decoys; modalities active, passive)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | passive | 100% / 92% / 96% (84–100) | 11 / 0 / 1 / 0 | n/a | 89% | 0% | 92% / 100% | 0 | 0 | 1.8 |
| ai-infra-guard | active | 100% / 81% / 90% (84–96) | 26 / 0 / 6 / 50 | 100% | 65% | 17% | 100% / 100% | 0 | 0 | 1.2 |

| Tool | active P / R / F1 | passive P / R / F1 |
|---|---|---|
| shadowscan | not run | 100% / 92% / 96% |
| ai-infra-guard | 100% / 81% / 90% | not run |

### runtime (40 cases, 24 positive; 98 expected entities, 165 decoys; modalities live, snapshot)

| Tool | Modalities | P / R / F1 | TP / FP / FN / TN | Specificity | Agent recall | Agent false alarms | Case recall / specificity | Errors | Incomplete | Seconds median |
|---|---|---|---|---|---|---|---|---|---|---|
| shadowscan | live, snapshot | 78% / 63% / 70% (63–76) | 62 / 17 / 36 / 148 | 90% | 77% | 11% | 100% / 56% | 0 | 20 | 1.9 |
| agentmesh-discovery | live | 100% / 12% / 22% (11–32) | 6 / 0 / 42 / 81 | 100% | 24% | 0% | 50% / 100% | 0 | 0 | 0.3 |
| fleet-ai-tools | live | 100% / 10% / 19% (0–34) | 5 / 0 / 43 / 81 | 100% | 20% | 0% | 25% / 100% | 0 | 0 | 0.0 |

| Tool | live P / R / F1 | snapshot P / R / F1 |
|---|---|---|
| shadowscan | 81% / 60% / 69% | 77% / 66% / 71% |
| agentmesh-discovery | 100% / 12% / 22% | not run |
| fleet-ai-tools | 100% / 10% / 19% | not run |

## Paired comparison

Exact McNemar test on case-level correctness against the reference tool, over cases both tools ran.

| Tool | Reference | Tool right, reference wrong | Reference right, tool wrong | p |
|---|---|---|---|---|
| agentdiscover | shadowscan | 0 | 26 | 0.000 |
| ai-infra-guard | shadowscan | 0 | 0 | 1.000 |
| vet | shadowscan | 4 | 26 | 0.000 |
| agentmesh-discovery | shadowscan | 2 | 36 | 0.000 |
| fleet-ai-tools | shadowscan | 6 | 25 | 0.001 |
| snyk-agent-scan | shadowscan | 0 | 13 | 0.000 |
| numbat | shadowscan | 0 | 17 | 0.000 |
| cisco-mcp-scanner | shadowscan | 0 | 19 | 0.000 |

