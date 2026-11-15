"""Step 3: send the summary to the selected LLM (claude | local)."""
import json
import os
from datetime import datetime
from typing import Callable

import anthropic
import httpx

from . import tools
from .models import CaptureMeta

# Language the final report is written in (e.g. "English", "Turkish").
REPORT_LANGUAGE = os.getenv("REPORT_LANGUAGE", "English")

SYSTEM_PROMPT = f"""You are an experienced network / Kubernetes troubleshooting expert.
You will receive a summary of a pcap extracted with zeek and tshark, plus the user's context.
- Rely only on evidence in the data; cite the relevant metric/line for every inference.
- If the data is insufficient, say so explicitly and suggest which additional capture/command is needed.
- Keep the difference between the pod network and the node network in mind (encapsulation, MTU, overlay).
- If earlier captures of the same problem are provided, compare the current capture against them:
  which metrics changed, whether the problem got worse or better, and whether earlier recommendations appear to have worked.
  State the time gap and concrete numbers in the comparison; don't re-explain what stayed the same at length.
Output format ({REPORT_LANGUAGE}, markdown): 1) Summary  2) Evidence  3) Likely root causes (most likely first)  4) Recommended next steps
If earlier captures were provided, add a "Changes vs. previous captures" section after section 2."""

TOOL_PROMPT = f"""

## Running additional commands ({tools.TOOL_NAME})
- If the data in the summary isn't enough to answer a question, you can run a targeted tshark command on the pcap with {tools.TOOL_NAME}.
- Every command is shown to the user before it runs; the user can approve, edit, or reject it.
  In the `purpose` field, briefly explain what the command will verify and how it could change the conclusion.
- At most {tools.MAX_TOOL_CALLS} commands in total. If the existing data is sufficient, write the report without proposing commands;
  don't propose "nice to have" commands, only ones that could change the conclusion.
- Propose independent commands together (multiple calls in one response) so the user can review them at once.
- If the user rejects a command, don't insist; continue with the data you have and state in the report what could not be verified.
- For every inference based on command output, say which command it came from.
- Once the report is done, don't propose more commands; commands you list under "Recommended next steps" should be ones the user
  needs to run in their own environment (on the live system, on other captures)."""


def system_prompt(tools_enabled: bool) -> str:
    return SYSTEM_PROMPT + (TOOL_PROMPT if tools_enabled else "")


# Earlier runs are clipped so they don't bloat the prompt.
HISTORY_REPORT_CHARS = 6000
HISTORY_RESULT_CHARS = 3000


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n... ({len(text) - limit} characters clipped)"


def _ago(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} sec"
    if seconds < 3600:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"


def build_history(previous: list[dict], current_submitted_at: str) -> str:
    """previous: output of db.previous_runs (oldest first).

    Wrapped in XML tags so markdown headings in earlier results don't get mixed up with the prompt's sections.
    """
    now = datetime.fromisoformat(current_submitted_at)
    parts = []
    for r in previous:
        meta = json.loads(r["metadata"])
        ago = _ago((now - datetime.fromisoformat(r["created_at"])).total_seconds())
        block = [f'<previous_run id="{r["id"]}" submitted_at="{r["created_at"]}" before_current="{ago}">',
                 f"capture_point: {meta.get('capture_point') or '-'}",
                 f"question: {meta.get('question')}",
                 f"<report>\n{_clip(r['report'] or '', HISTORY_REPORT_CHARS)}\n</report>"]
        if r["result"]:
            block.append(f"<assessment>\n{_clip(r['result'], HISTORY_RESULT_CHARS)}\n</assessment>")
        block.append("</previous_run>")
        parts.append("\n".join(block))
    return "\n\n".join(parts)


def build_prompt(meta: CaptureMeta, report: str, history: str = "") -> str:
    prompt = f"## Context\n```json\n{meta.model_dump_json(indent=2)}\n```\n\n"
    if history:
        prompt += f"## Earlier captures of the same problem (oldest first)\n{history}\n\n"
    prompt += (f"## Current capture — analysis output\n```\n{report}\n```\n\n"
               f"## Question\n{meta.question}")
    return prompt


ProgressFn = Callable[[int], None]  # number of output characters generated so far

# USD per million tokens: (input, output, cache read). Cache writes (5-minute TTL) cost 1.25 × input.
# Used only for the estimated cost shown in the UI; override with MODEL_PRICES_JSON if prices change.
MODEL_PRICES = {
    "claude-opus-5-5": (4.0, 20.0, 0.20),
    "claude-fable-5-2": (8.0, 40.0, 0.20),
    "claude-sonnet-5-5": (2.0, 10.0, 0.10),
    "claude-opus-5": (5.0, 25.0, 0.50),
    "claude-opus-4-8": (5.0, 25.0, 0.50),
}
MODEL_PRICES.update({k: tuple(v) for k, v in json.loads(os.getenv("MODEL_PRICES_JSON", "{}")).items()})


def usage_of(msg) -> dict:
    """Token usage of one response plus its estimated cost (fallback turns are priced at the served model)."""
    u = msg.usage
    usage = {
        "input_tokens": getattr(u, "input_tokens", 0) or 0,
        "output_tokens": getattr(u, "output_tokens", 0) or 0,
        "cache_read_input_tokens": getattr(u, "cache_read_input_tokens", 0) or 0,
        "cache_creation_input_tokens": getattr(u, "cache_creation_input_tokens", 0) or 0,
        "turns": 1,
    }
    price_in, price_out, price_cache_read = MODEL_PRICES.get(
        getattr(msg, "model", None), MODEL_PRICES.get(os.getenv("CLAUDE_MODEL", "claude-opus-5-5"), MODEL_PRICES["claude-opus-5-5"]))
    usage["cost_usd"] = round((usage["input_tokens"] * price_in
                               + usage["output_tokens"] * price_out
                               + usage["cache_read_input_tokens"] * price_cache_read
                               + usage["cache_creation_input_tokens"] * price_in * 1.25) / 1_000_000, 6)
    return usage


def claude_turn(messages: list[dict], tools_enabled: bool, on_progress: ProgressFn | None = None,
                system: str | None = None):
    """Generate the next assistant turn of the conversation (returns a BetaMessage).

    While waiting for approval the conversation is stored in the DB and resumed from here later.
    The system prompt and tool list must therefore stay byte-identical for the whole conversation
    (`system` and `tools_enabled` are fixed at the start and stored), and earlier messages are
    sent back completely unchanged.
    """
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from the environment
    kwargs = dict(
        model=os.getenv("CLAUDE_MODEL", "claude-opus-5-5"),
        max_tokens=32000,
        system=system if system is not None else system_prompt(tools_enabled),
        output_config={"effort": "high"},
        # Server-side fallback: if the model declines the request, the API automatically falls back to a suitable model.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        cache_control={"type": "ephemeral"},  # history re-sent on tool turns is read from the cache
        messages=messages,
    )
    if tools_enabled:
        kwargs["tools"] = [tools.TOOL_SCHEMA]
    for attempt in range(3):
        try:
            with client.beta.messages.stream(**kwargs) as stream:
                written = 0
                for text in stream.text_stream:
                    written += len(text)
                    if on_progress:
                        on_progress(written)
                return stream.get_final_message()
        except anthropic.APIError:
            raise
        except ValueError:
            # eager_input_streaming: the SDK couldn't parse the tool input at all, so there's no tool_use_id → retry the request
            if attempt == 2:
                raise


def ask_claude(prompt: str, on_progress: ProgressFn | None = None) -> str:
    """One-shot analysis without tools."""
    msg = claude_turn([{"role": "user", "content": prompt}], tools_enabled=False, on_progress=on_progress)
    if msg.stop_reason == "refusal":
        raise RuntimeError("Claude declined the request.")
    return "".join(b.text for b in msg.content if b.type == "text")


def ask_local(prompt: str) -> str:
    # OpenAI-compatible endpoint: Ollama, vLLM, llama.cpp server, LM Studio...
    base = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/v1")
    resp = httpx.post(
        f"{base}/chat/completions",
        json={
            "model": os.getenv("LOCAL_LLM_MODEL", "llama3.1"),
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        },
        timeout=600,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def analyze(provider: str, meta: CaptureMeta, report: str,
            on_progress: ProgressFn | None = None, history: str = "") -> str:
    prompt = build_prompt(meta, report, history)
    if provider == "claude":
        return ask_claude(prompt, on_progress)
    if provider == "local":
        return ask_local(prompt)
    raise ValueError(f"Unknown provider: {provider}")
