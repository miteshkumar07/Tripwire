"""Thin helpers around the Anthropic client shared by extractor and planner."""
import json


class LLMOutputError(ValueError):
    pass


def default_client():
    import anthropic
    return anthropic.Anthropic()


def response_json(resp):
    """Parse the JSON text block of a structured-output response."""
    if getattr(resp, "stop_reason", None) == "refusal":
        raise LLMOutputError("model refused")
    text = next((b.text for b in resp.content if getattr(b, "type", None) == "text"), None)
    if text is None:
        raise LLMOutputError("no text block in response")
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise LLMOutputError(f"invalid JSON: {e}") from e


def add_usage(total: dict, resp) -> None:
    usage = getattr(resp, "usage", None)
    total["input_tokens"] = total.get("input_tokens", 0) + (getattr(usage, "input_tokens", 0) or 0)
    total["output_tokens"] = total.get("output_tokens", 0) + (getattr(usage, "output_tokens", 0) or 0)
