# repo-ua-parser

Tiny user-agent parser used by the edge log pipeline: browser family, OS
family and robot classification. Zero runtime dependencies.

Internal clone: `git@git.adatum.example:platform/repo-ua-parser.git`

## Robot coverage

Classic crawlers come from `data/crawlers.json`. AI-era crawlers and
assistant fetchers are matched by the generic robot heuristics; the
fixture corpus under `tests/fixtures/` pins the ones we see most at the
edge:

| Token | Operator note |
| --- | --- |
| `GPTBot`, `OAI-SearchBot`, `ChatGPT-User` | OpenAI crawler and assistant fetchers |
| `ClaudeBot`, `Claude-Web`, `anthropic-ai` | Anthropic crawler tokens |
| `PerplexityBot`, `Perplexity-User` | Perplexity crawler and assistant fetcher |
| `Google-Extended` | robots.txt control token, never a UA |
| `CCBot` | Common Crawl |
| `Bytespider` | ByteDance |
| `meta-externalagent` | Meta training fetcher |

Nothing in this library calls any of these services; the tokens above are
log *subjects* that the parser must label correctly.

## Usage

    import { parse } from "@adatum/ua-robot-parser";

    parse(request.headers["user-agent"]);
    // { browser: "chrome", os: "windows", robot: false, robotName: null }
