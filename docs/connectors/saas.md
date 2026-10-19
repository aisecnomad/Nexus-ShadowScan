# SaaS connectors

SaaS connectors discover bots, apps, integrations, and AI-related marketplace
installations across collaboration and productivity platforms.

!!! info "Live and offline"
    SaaS connectors support live API collection and offline JSON/CSV export
    analysis (including CASB inventory exports via `saas.generic`).

See the [shared connector entry guide](../connectors.md#connector-entry-guide)
for the common modes, permissions, options, fail-closed and evidence-limit
references.

Display names, publisher labels and descriptions follow the same
[product-attribution rules](identity.md#ambiguous-product-names) as identity
connectors: every name is provisional until same-product non-name evidence
corroborates it. An app's existence, installation or ordinary permissions cannot
establish a name's claimed AI vendor. Name-only records can remain useful inventory
hints at possible confidence.

## `saas.slack`
`users.list` (bots), `admin.apps.approved.list` / `restricted` / `requests`
(scopes, pending requests), `team.integrationLogs` (who installed what).
`team.info` must return an authenticated workspace identity. If `team_id` is
configured, it must match exactly before inventory calls begin. `team_id` is
then sent with `users.list`, the `admin.apps.*` lists and `team.integrationLogs`:
Slack requires it from an org-level token (the Enterprise token the
`admin.apps.*` lists need) and ignores it from a workspace-level token, so set
it whenever the token is an org-level one. Missing/null
collection arrays and malformed pagination are incomplete coverage. Later
network failures retain already collected observations; provider error text is
not copied into diagnostics. Complete live acceptance generally requires an
appropriately scoped administrative audit token, not an ordinary bot token.
The Slack app id is passed to signature matching as the app's client id, so a
rule pack's `client_id` signal can bind a reviewed Slack app. AI meeting
note-takers include Wudpecker and Tactiq by name and by their `wudpecker.io`
and `tactiq.io` homepage domains.

## `saas.microsoft-teams`
Graph app catalog (custom apps with bot definitions and RSC permissions) and
installed apps per team (capped by `max_teams`).
Findings retain catalog and installed-version definitions together, without
assuming catalog order identifies the current version. `definition_observations`
records definition IDs, versions, bot IDs, requested RSC permissions and
installation/team provenance, one entry per distinct definition and source: an
installed definition carries `installation_count`, `team_count` and `teams`, a
sorted sample of at most 20 team IDs and names, so the finding stays bounded
however many teams install the app. At most 20 observations are listed, in
sorted order, and `definition_observations_omitted` counts the rest; `versions`
and `bot_ids` list at most 20 observed values each, with `versions_omitted` and
`bot_ids_omitted`, so the finding stays bounded however many distinct
definitions an export holds. Requested permissions do not establish granted
access. Permissions, scalar fields and conflict detection read every
observation: contradictory observations of the same definition ID or version
mark coverage incomplete while retaining the attributed evidence. Scalar
`version`, `bot_id` and `publishing_state` are populated only when one nonempty
value was observed; otherwise they are `null`.

## `saas.github-apps`
Org installations with permissions and repository selection (AI reviewers,
coding agents), Copilot billing/seat settings, fine-grained PATs approved for
the org. An installation is reported when it matches an AI signature or has an
AI-like name; write access alone does not make an app an agent. Set
`include_unrecognized_apps: true` to also report other write-capable apps,
tagged `unrecognized-app` and capped at possible confidence. `workflows` or
`actions` write access implies `code-exec`; contents and pull-request writes
are SaaS write actions.

Tokens: GitHub lists the fine-grained PATs approved for an organisation
(`GET /orgs/{org}/personal-access-tokens`) only to a GitHub App installation or
user access token with the organization "Personal access tokens" read
permission; a classic or fine-grained personal token is refused there. A GitHub
App token with the organization "Administration", "Personal access tokens" and
"GitHub Copilot Business" read permissions covers the installations, Copilot
billing and PAT calls alike. With an organization owner's personal token as
`token`, set `app_token` (env `GITHUB_APP_TOKEN`) to a GitHub App token for the
PAT list; without it that listing is refused and the scan is incomplete, with a
warning that names `app_token`.

Live installation pages must report a nonnegative integer `total_count` that
stays unchanged throughout pagination. The connector compares it with unique
installation IDs; missing or malformed counts, duplicate or invalid IDs,
changed totals, and a listing that ends before its declared total all make
coverage incomplete. Already collected observations remain available.
Offline `{"total_count": ..., "installations": [...]}` envelopes receive
the same count checks across each export file: one envelope holding every
installation, or one page envelope per line as `gh api --paginate
/orgs/ORG/installations | jq -c .` writes them. Every page in a file must
declare the same total, and the unique installations across the file must
match it; each problem is reported once per file. A file is one listing, so
keep each organisation's pages in a file of their own. Legacy offline
`{"installations": [...]}` envelopes and bare record lists remain supported
without asserting a provider total, as long as no page of the same file declares
one. These checks detect inconsistent inventories but cannot guarantee snapshot
consistency when apps change during collection.

## `saas.atlassian`
UPM user-installed apps for Jira and Confluence. Set `site` to the concrete
HTTPS site origin for offline exports as well as live collection. App keys
are shared across sites, so approvals must also name the site in
`discovery.accounts`. Missing site identity leaves discovery incomplete and
generated cards unbound pending review. URL host case, a default HTTPS port
and a trailing slash are normalized; app resource IDs remain case-sensitive.

Without a configured `site`, finding IDs are bound to the resolved path of
each export file: the same app key in two files stays two findings, and moving
or renaming a file changes its IDs. Finding IDs from earlier releases change
for unscoped exports and for a `site` with an uppercase host or an explicit
`:443`; configure the canonical site, rescan and take a fresh baseline. Keep one
site's exports per scan input. A `site` must be a plain HTTPS origin
(`https://<host>`): a missing scheme, `http://`, a path such as a Data Center
context path, user information, a query, a fragment, a trailing dot or a
non-ASCII host stops the connector with exit 3.

## `saas.notion`
Notion bot users. A bot is inventoried when non-name evidence
establishes an AI product or provider, or when its name is an AI-name hint, as
for GitHub Apps: a generic AI word ("Internal LLM Agent", "Acme AI Assistant",
"Support GPT") or an ambiguous product name such as Gemini. Every Notion
integration is a bot user, so the word "bot" alone ("Jira Bot") is not a hint
here. A hint never attributes a product: the bot's own observation is bounded
at possible confidence and a name-only product stays under
`metadata.potential_frameworks`. A nameless bot (its id is never matched as a
name) or an ordinary sync integration is not reported, because a bot's
existence and owner do not identify AI. A missing or repeated pagination cursor, or reaching the live
page cap (`max_pages`, at most 1000), makes the scan incomplete.

## `saas.zoom`
The Marketplace list API returns approved public apps and account-created apps
(`type=public` and `type=account_created`), including app scopes when supplied.
See [Zoom's Marketplace List apps API](https://developers.zoom.us/docs/api/marketplace/).
Approval or account creation does not establish that any individual installed
or used the app; obtain a separate tenant activity or installation export to
check that. Denied, invalid, or truncated pages make the scan incomplete.

## `saas.generic`
Any CSV/JSON app inventory (Google Marketplace, HubSpot, CASB discovered-apps
exports…). Map columns with `fields:`; findings are produced for AI matches
and privileged/data scopes (`keep_all: true` to emit everything). A record without an app name is
skipped and makes the scan incomplete (fully blank rows are ignored); valid
neighboring records are still reported. An export where no record maps to a
name is reported with the accepted column names instead of looking empty.
Whole-record credential context is applied before selecting, splitting or
shortening fields for matching and reports. A known credential copied into an
app name, scope or other display field is withheld even when its original
credential column is omitted from findings. Credential contents do not establish
product or permission evidence. Every value under a credential column name is
learned however it looks (`Abcd1234`, `12345678`, `MyTestPassword99`), except a
placeholder as the whole value (`none`, `****`, `xxxxxxxx`, `changeme`,
`your_secret`, `<secret>`, `${SECRET}`), which withholds nothing, and a value
shorter than eight characters. A short value withholds only a field equal to it
(an app ID equal to it is withheld from the resource), and nothing when it is a
flag (`N`, `-`, `Yes`, `N/A`: a yes/no or not-applicable word, or at most one
letter or digit); a short credential inside a longer field (`ChatGPT hunter2`)
is still shown. A record whose name a credential withholds entirely is skipped
and makes the scan incomplete. Sanitization limits make coverage incomplete.
When a credential is redacted from a resource, the finding ID combines the
redacted resource with a keyed pseudonym of the raw one: distinct resources keep
distinct IDs, and the finding records `metadata.identity_scope` (`run`,
scan-local, unless `SHADOWSCAN_IDENTITY_KEY` makes it `keyed`).

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
