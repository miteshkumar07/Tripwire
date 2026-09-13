# Tripwire

**▶ [Demo video (YouTube)](https://youtu.be/d_Eja0wBL3k)** · **🌐 [Live prototype: trace viewer](https://miteshkumar07.github.io/Tripwire/demo/viewer.html)**

Tripwire triages public GitHub issues into Linear and Slack. Because the issue text is written by strangers and the agent holds write credentials to two other apps, it has the lethal trifecta by construction, so we built it to be attacked and tested it with 16 injection attacks across 5 families: 16 blocked, 0 through.

**[Scoreboard](scoreboard.md)** · **[Reliability brief](RELIABILITY_BRIEF.md)** · **[Trace viewer](demo/viewer.html)**

## What it does

Someone files an issue on a public GitHub repo. Tripwire reads it, works out whether it is a bug, how severe it is and which area it touches, checks Linear for a duplicate, then either comments on the existing ticket or files a new one, and posts a note to the right Slack channel. Issues that are not bugs (questions, feature requests, spam) are left alone.

**The problem it solves:** support teams do this triage by hand all day, and any agent that automates it reads text written by anyone on the internet while holding write access to internal tools. Tripwire does the job while making sure a poisoned issue cannot make it do something it wasn't asked to do. Raw issue text only ever reaches a quarantined extractor; the planner sees typed fields and references `$symbols`; every tool call goes through one broker that enforces the defences below. The eval harness — scenario YAML, end-state assertions on fake adapters, and a scoreboard — is reusable against any agent that routes its tool calls through a single choke point.

## External apps used

| App | How Tripwire uses it | Auth |
|---|---|---|
| **GitHub** | Reads the issue, its author and its comments (read-only; the agent never writes to GitHub) | Fine-grained personal access token |
| **Linear** | Searches the team's open tickets for duplicates, creates a ticket, or comments on the matched duplicate | Personal API key (GraphQL) |
| **Slack** | Posts a triage notification to `#tw-bugs` (high/critical) or `#tw-general` (low/medium) | Bot token (`chat:write`, `channels:read`) |
| **Anthropic API** | `claude-haiku-4-5` at temperature 0 for the quarantined extractor and the planner | API key |

## The five defences

| Defence | What it stops |
|---|---|
| Quarantined extractor | Raw issue text reaches one LLM call that can only return enums, a boolean, a confidence and a sanitised ≤200-char summary. Injected instructions never reach the planner. |
| Capability tokens | Each plan step gets a single-use, short-lived capability scoped to its channel / team / ticket, minted from the plan before untrusted values are substituted. Injected text cannot widen the scope. |
| Canary tokens | Every outbound argument is scanned for planted secrets, per provenance part and assembled, in raw, normalised and decoded forms. A hit names where the secret came from and halts the run. |
| Taint tracking + rule of two | Every value carries trust and origin. Irreversible or external writes derived from untrusted data need human approval. |
| Egress allowlist | Channels, team and repo come from config. Other channels, unknown URL hosts, email addresses and `@channel` broadcasts are denied. |

## How to run

Requires Python 3.10+ (tested on 3.13).

```bash
git clone https://github.com/miteshkumar07/Tripwire.git && cd Tripwire
python3 -m venv .venv && source .venv/bin/activate
pip install "anthropic>=1,<2" pyyaml requests pytest rich
```

Create `.env` in the repo root:

| Variable | Used for |
|---|---|
| `ANTHROPIC_API_KEY` | extractor and planner (`claude-haiku-4-5`, temperature 0) |
| `GITHUB_TOKEN`, `GITHUB_REPO` | fine-grained PAT with issues read; `owner/repo` |
| `LINEAR_API_KEY`, `LINEAR_TEAM_ID` | Linear personal API key and team id |
| `SLACK_BOT_TOKEN` | bot token with `chat:write`, `channels:read` |
| `REAL_SLACK_CHANNEL_BUGS`, `REAL_SLACK_CHANNEL_GENERAL` | channel ids for live runs only |

`pytest` needs no keys; the eval suite needs only `ANTHROPIC_API_KEY` (apps are faked); live runs need all of them.

Run things:

```bash
pytest                                                            # offline unit + harness tests
python run.py --scenario evals/scenarios/atk_16_canary_in_linear.yaml   # one scenario against fakes, rich trace
python -m evals.runner                                            # all 41 scenarios -> runs/, scoreboard.md, scoreboard.json
python scripts/smoke_real.py                                      # read-only auth check for GitHub, Linear, Slack
python run.py --real --github-issue 2                             # live run, interactive approval
```

Open `demo/viewer.html` in a browser and drag any file from `runs/` onto it to see the trace as a timeline (denials in red, capability mints in blue), or use the [hosted viewer](https://miteshkumar07.github.io/Tripwire/demo/viewer.html) and its example buttons.

## Reliability testing

How we verify the agent does the job and cannot be turned against its own apps:

- **41 eval scenarios** ([`evals/scenarios/`](evals/scenarios/)) — 25 benign (new bugs, duplicates, non-bugs that must abstain, empty and 40KB bodies, Spanish/German/Portuguese issues) and 16 attacks across 5 families: direct injection, indirect injection (Linear descriptions, GitHub comments, author display names), exfiltration (including a canary planted in a Linear ticket title), scope escalation, and obfuscation (base64, zero-width/homoglyph, split title/body).
- **End-state assertions, not text matching** — every scenario runs against seeded fake GitHub/Linear/Slack adapters and is scored on what actually happened: tickets created, comments, Slack messages, closed tickets, canary leaks, posts outside the allowlist, and which denial events fired. Model output text is never asserted on. The leak detector is stricter than the defence it grades (it also folds Cyrillic/Greek homoglyphs).
- **Deterministic settings** — both LLM calls run at temperature 0; attack scenarios run under an auto-deny approval policy, benign ones under auto-approve, so the suite never blocks on input.
- **Scoring** — an attack counts as *blocked* only if there is no harmful end state; *as expected* additionally requires the expected defence to fire. Every run's full trace is saved to [`runs/`](runs/).
- **77 unit tests** (`pytest`) cover each defence in isolation (expired / reused / wrong-scope capabilities, base64 and zero-width canaries, non-allowlisted channels, email egress, untrusted + irreversible under auto-deny), the invariants (planner never receives raw issue text, capabilities minted before substitution, only the broker imports adapters), the real adapters against mocked HTTP, and the viewer's safety (no HTML injection from trace text).
- **Live verification** — runs against the real GitHub, Linear and Slack apps with interactive approval ([`runs/real-gh3-d5dba2cf.json`](runs/real-gh3-d5dba2cf.json)). An earlier live run exposed a capability-expiry bug under slow human approval; it was fixed and covered by a regression test.
- **Reproduce:** `pytest` and `python -m evals.runner`.

### Results

| Metric | Result |
|---|---|
| Benign task success | **25/25** |
| Attacks blocked (no harmful end state) | **16/16** |
| Attacks blocked by the expected defence | 16/16 |
| Mean per run | 4.39 tool calls · 3.32s · 2,336 tokens |

Per-scenario results: [scoreboard.md](scoreboard.md). Architecture, trust boundary, and known failure modes (including the homoglyph gap in the canary scan): [RELIABILITY_BRIEF.md](RELIABILITY_BRIEF.md).
