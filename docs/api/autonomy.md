# Autonomy

The autonomy module assigns each applicable finding a tier on the **L0–L5 autonomy scale**,
from fully supervised chatbot to fully autonomous AI system.

## The scale

| Tier | Name | Description |
|------|------|-------------|
| **L0** | Chatbot | Responds to human-initiated queries; no memory, no external action |
| **L1** | Copilot | Assists with human tasks; suggests actions but does not execute them |
| **L2** | Supervised agent | Can execute actions with human approval at each step |
| **L3** | Delegated agent | Executes multi-step tasks; human checkpoints on outcomes |
| **L4** | Autonomous agent | Self-directed; initiates and completes goals without per-action oversight |
| **L5** | Fully autonomous | Operates continuously; redesigns own goals or spawns sub-agents |

## Evidence interval

ShadowScan assigns an **interval** `[floor, ceiling]` rather than a point estimate, because
the scanner can prove a capability exists but rarely prove one is absent:

- **`floor`** rises only when evidence proves a higher level (e.g. a `schedule` initiation
  signal confirms at least L4).
- **`ceiling`** falls only on positive restriction evidence (e.g. a `requires_approval`
  governance flag caps at L2).
- **Unknown never counts as low**: absent evidence keeps the ceiling at 5.

The interval also carries `oversight` (`bypassed`, `gated` or `unknown`) and `initiation`
(`schedule`, `event`, `human` or `unknown`), with a `basis` list naming the rules that
determined each value.

## Functions

`classify()` is a pure function of the finding — no external state. `apply_autonomy()` widens
the interval to include any level a matched inventory entry declares. `merge_autonomy()`
classifies a finding merged from several fleet reports, unioning the evidence from all sources.

See the [autonomy concepts page](../concepts/autonomy.md) for the full rule set.

::: shadowscan.autonomy
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
