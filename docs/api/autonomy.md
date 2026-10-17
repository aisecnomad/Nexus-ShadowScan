# Autonomy

The autonomy module records how much an AI system can do without a person. Each finding of a
kind in `APPLICABLE_KINDS` gets an interval on the six-level scale in `LEVELS`, stored as
`metadata.autonomy` (schema `shadowscan.autonomy/v1`).

## The scale

| Level | Label | Machine name |
|-------|-------|--------------|
| **L0** | Chatbot | `chatbot` |
| **L1** | Copilot | `copilot` |
| **L2** | Supervised | `supervised` |
| **L3** | Semi-Autonomous / Agentic Workflow | `semi-autonomous` |
| **L4** | High Autonomy | `high-autonomy` |
| **L5** | Fully Autonomous | `fully-autonomous` |

The [autonomy concepts page](../concepts/autonomy.md#scale) describes what each level means.

## Evidence interval

ShadowScan assigns an **interval** `[floor, ceiling]` rather than a point estimate, because
the scanner can prove a capability exists but rarely prove one is absent:

- **`floor`** rises only on evidence. For example, kind `workflow` proves at least L3, and
  approval-bypass evidence together with capability `saas-actions`, `code-exec`,
  `delegated-identity` or `data-access` proves L4. A `schedule` or `event` initiation raises
  the floor to L5 only on top of those two.
- **`ceiling`** falls only on positive restriction evidence: `metadata.approval_gate.scope`
  `every-action`, with no approval-bypass evidence, caps it at L2.
- **Unknown never counts as low**: without restriction evidence the ceiling stays at 5.

The block also carries `oversight` (`bypassed`, `gated` or `unknown`), `initiation`
(`schedule`, `event`, `human` or `unknown`) and a `basis` list of at most 32
`{bound, rule, value}` entries naming the rules, from the closed set in `RULES`, that set
each value.

## Functions

`classify()` is a pure function of the finding. It returns None for a kind outside
`APPLICABLE_KINDS`. `apply_autonomy()` writes the block, replacing any earlier one. When a
matched inventory entry declares a level, it records `declared` and `declared_source`. A
declared level below the floor adds the tag `autonomy-understated`, and one above the ceiling
adds the basis note `declared-above-ceiling`. The interval itself is never moved to fit the
declaration. `merge_autonomy()` classifies a finding merged from several reports with the
widest oversight and initiation any source block records. It then widens the result so it
admits at least what every source block admits.

See the [autonomy concepts page](../concepts/autonomy.md) for the full rule set.

::: shadowscan.autonomy
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
