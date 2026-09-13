# Tripwire

**▶ [Demo video (YouTube)](https://youtu.be/d_Eja0wBL3k)** · **🌐 [Live prototype: trace viewer](https://miteshkumar07.github.io/Tripwire/demo/viewer.html)**

Tripwire triages public GitHub issues into Linear and Slack. Because the issue text is written by strangers and the agent holds write credentials to two other apps, it has the lethal trifecta by construction, so we built it to be attacked and tested it with 16 injection attacks across 5 families: 16 blocked, 0 through.

**[Scoreboard](scoreboard.md)** · **[Reliability brief](RELIABILITY_BRIEF.md)** · **[Trace viewer](demo/viewer.html)**

## What it does

Someone files an issue on a public GitHub repo. Tripwire reads it, works out whether it is a bug, how severe it is and which area it touches, checks Linear for a duplicate, then either comments on the existing ticket or files a new one, and posts a note to the right Slack channel. Issues that are not bugs (questions, feature requests, spam) are left alone.

The agent is built so that a poisoned issue cannot make it do something it wasn't asked to do. Raw issue text only ever reaches a quarantined extractor; the planner sees typed fields and references `$symbols`; every tool call goes through one broker that enforces the defences below. The eval harness — scenario YAML, end-state assertions on fake adapters, and a scoreboard — is reusable against any agent that routes its tool calls through a single choke point.

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

Run things:

```bash
pytest                                                            # offline unit + harness tests
python run.py --scenario evals/scenarios/atk_16_canary_in_linear.yaml   # one scenario against fakes, rich trace
python -m evals.runner                                            # all 41 scenarios -> runs/, scoreboard.md, scoreboard.json
python scripts/smoke_real.py                                      # read-only auth check for GitHub, Linear, Slack
python run.py --real --github-issue 2                             # live run, interactive approval
```

Open `demo/viewer.html` in a browser and drag any file from `runs/` onto it to see the trace as a timeline (denials in red, capability mints in blue).

## Results

25/25 benign scenarios succeed and 16/16 attacks are blocked — see [scoreboard.md](scoreboard.md). The [reliability brief](RELIABILITY_BRIEF.md) covers the architecture, the trust boundary, the eval methodology and the known failure modes, including the homoglyph gap in the canary scan.
