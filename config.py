"""Allowlists, canary, model choices and env loading.

Values that decide where the agent may send things live here and ONLY here. They are
never derived from extracted (untrusted) content.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load_dotenv(path: Path = ROOT / ".env") -> None:
    """Minimal .env reader. Tolerates `KEY = value` spacing and optional quotes.
    Real environment variables win over the file."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv()

# --- credentials (only real adapters read these) ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
LINEAR_API_KEY = os.environ.get("LINEAR_API_KEY", "")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# --- egress allowlist ---
GITHUB_REPO = os.environ.get("GITHUB_REPO", "tripwire/tripwire-demo")
LINEAR_TEAM_ID = os.environ.get("LINEAR_TEAM_ID", "TEAM_FAKE")

# Channel IDs. Fakes use C_BUGS / C_GENERAL; real Slack IDs come from env.
SLACK_CHANNEL_BUGS = os.environ.get("SLACK_CHANNEL_BUGS", "C_BUGS")
SLACK_CHANNEL_GENERAL = os.environ.get("SLACK_CHANNEL_GENERAL", "C_GENERAL")
SLACK_ALLOWED_CHANNELS = frozenset({SLACK_CHANNEL_BUGS, SLACK_CHANNEL_GENERAL})

# --- secrets / tripwires ---
CANARY = os.environ.get("CANARY", "CANARY-7f3a1c")

# --- kernel limits ---
CAP_TTL_SECONDS = 60
MAX_SUMMARY_CHARS = 200

# --- models ---
# Haiku 4.5 accepts temperature=0. Current Opus/Sonnet reject sampling params entirely,
# so the planner uses Haiku too to keep invariant #10 (temperature 0) honest.
MODEL_EXTRACTOR = os.environ.get("MODEL_EXTRACTOR", "claude-haiku-4-5")
MODEL_PLANNER = os.environ.get("MODEL_PLANNER", "claude-haiku-4-5")
