---
title: Hardening log
---

!!! warning "Self-review record, not an independent audit"
    This page publishes the maintainer's own hardening record. ShadowScan's
    single maintainer wrote it with AI assistance while changing the code it
    describes, from that AI-assisted self-review and from automated checks such
    as CodeQL. No second person or third party has verified its findings, its
    regression claims or its disposition. It is not an independent security
    audit, a second-person review or live tenant acceptance, and must not be
    cited as one. Scorecard, CI, CodeQL and the files under `archive/reviews/`
    are not independent human review either; see
    [governance](../governance.md).

Below is the consolidated hardening log of 24 September 2026, included from
[`archive/reviews/consolidated-review-2026-09-24.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/archive/reviews/consolidated-review-2026-09-24.md).
It is kept as written, except that its links to other documents are absolute
so that they resolve here too. It describes the tree, the pull requests and
the repository settings as they were on that date. For the controls as they
are now, read [controls and limits](controls.md) and the
[threat model](threat-model.md).

The other records from the same hardening work are in the repository, with
the same status:

| Record | What it covers |
|---|---|
| [`production-review-2026-09-24.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/archive/reviews/production-review-2026-09-24.md) | Production hardening log |
| [`production-review-2026-09-24-round2.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/archive/reviews/production-review-2026-09-24-round2.md) | Second production hardening round |
| [`security-review-2026-09-24.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/archive/reviews/security-review-2026-09-24.md) | Software and security hardening log |
| [`followup-review-2026-09-24.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/archive/reviews/followup-review-2026-09-24.md) | Follow-up security and reliability log |
| [`archive/reviews/`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/archive/reviews/README.md) | The index of every retained AI-assisted review record |

Every change since then has a detailed entry in the
[engineering log](../engineering-log.md) and a line in the
[changelog](../changelog.md). A reviewer who did not author the code can start
from the [external reviewer packet](../operations/reviewer-packet.md).

--8<-- "archive/reviews/consolidated-review-2026-09-24.md"
