"""Background queue: parses runs, sends them to the LLM and answers follow-up questions.

The DB is the source of truth; the in-memory queue only carries run ids. If the server
restarts, `queued`/`running` runs are read from the DB and queued again.

If Claude proposes a tshark command (tool_use), the run moves to `awaiting_approval` and the
worker thread is released (unless the analysis auto-approves commands). Once the user has decided
on every proposal, the run is queued again; the worker runs the approved commands, gives the
results to Claude and continues.

A follow-up question re-opens a finished run (`active_followup_id` is set): the worker appends the
question to the stored conversation and answers it; the run returns to `done` afterwards, keeping
its original result.
"""
import json
import logging
import os
import queue
import tempfile
import threading
import time
from pathlib import Path

from . import db, tools
from .llm import analyze, build_history, build_prompt, claude_turn, system_prompt, usage_of
from .models import CaptureMeta
from .parsers import build_report

log = logging.getLogger("pcap-analyzer.worker")

# LLM stage progress: 60 → 95, estimated from generated characters / expected length.
LLM_START, LLM_END = 60, 95
EXPECTED_ANSWER_CHARS = int(os.getenv("EXPECTED_ANSWER_CHARS", "6000"))
# Number of earlier runs given to the LLM for comparison.
HISTORY_RUNS = int(os.getenv("HISTORY_RUNS", "3"))
# Maximum number of Claude turns per analysis / follow-up (infinite-loop guard).
MAX_TURNS = tools.MAX_TOOL_CALLS + 4
CANCEL_CHECK_INTERVAL = 1.0  # seconds between DB checks for a cancel request


class Paused(Exception):
    """The run is waiting for user approval; the worker releases it."""


class Cancelled(Exception):
    """The user cancelled the run (or the follow-up being answered)."""


def process(run_id: int) -> None:
    if not db.claim_run(run_id):
        return  # deleted, taken by another worker, or not queued
    run = db.get_run(run_id)
    followup_id = run["active_followup_id"]

    last = {"stage": run["stage"], "progress": run["progress"], "checked": 0.0}

    def check_cancel(force: bool = False) -> None:
        now = time.monotonic()
        if force or now - last["checked"] >= CANCEL_CHECK_INTERVAL:
            last["checked"] = now
            if db.cancel_requested(run_id):
                raise Cancelled()

    def set_progress(stage: str, progress: int) -> None:
        if (stage, progress) != (last["stage"], last["progress"]):  # avoid redundant DB writes
            last.update(stage=stage, progress=progress)
            db.update_run(run_id, stage=stage, progress=progress)
        check_cancel()  # also aborts a streaming Claude response mid-way

    try:
        check_cancel(force=True)
        if followup_id:
            _answer_followup(run, followup_id, set_progress, check_cancel)
            return
        answer = _analyze(run, set_progress, check_cancel)
        if answer is not None:
            db.update_run(run_id, result=answer, status="done", stage="done", progress=100, finished_at=db.now())
    except Paused:
        db.update_run(run_id, status="awaiting_approval", stage="awaiting_approval")
        log.info("run %s is waiting for user approval", run_id)
    except Cancelled:
        log.info("run %s cancelled", run_id)
        if followup_id:
            _end_followup(run_id, followup_id, status="cancelled")
        else:
            db.update_run(run_id, status="cancelled", stage="cancelled", cancel_requested=0, finished_at=db.now())
            _reject_pending(run_id)
    except Exception as e:  # noqa: BLE001 — the error is stored; the worker keeps going
        log.exception("run %s failed", run_id)
        error = f"{type(e).__name__}: {e}"
        if followup_id:
            _end_followup(run_id, followup_id, status="failed", error=error)
        else:
            db.update_run(run_id, status="failed", stage="failed", error=error, finished_at=db.now())


def _reject_pending(run_id: int) -> None:
    for c in db.list_tool_calls(run_id):
        if c["status"] == "pending":
            db.update_tool_call(c["id"], status="rejected", user_note="cancelled", decided_at=db.now())


def _end_followup(run_id: int, followup_id: int, *, status: str, answer: str | None = None,
                  error: str | None = None) -> None:
    """Finish a follow-up; the run goes back to 'done' with its original analysis."""
    db.update_followup(followup_id, status=status, answer=answer, error=error, finished_at=db.now())
    _reject_pending(run_id)
    db.update_run(run_id, status="done", stage="done", progress=100, active_followup_id=None, cancel_requested=0)


# ---------------------------------------------------------------- initial analysis
def _analyze(run: dict, set_progress, check_cancel) -> str | None:
    run_id = run["id"]
    meta = CaptureMeta.model_validate_json(run["metadata"])
    if run["conversation"] is not None and run["report"] is not None:
        report = run["report"]  # resuming after approval / restart
    else:
        db.update_run(run_id, stage="zeek", progress=5, started_at=db.now())
        with tempfile.TemporaryDirectory() as tmp:
            report, stats = build_report(db.pcap_file(run["pcap_path"]), Path(tmp), meta, on_stage=set_progress)
        db.update_run(run_id, report=report, stats=json.dumps(stats))
        check_cancel(force=True)

    if run["dry_run"]:
        db.update_run(run_id, status="done", stage="done", progress=100, finished_at=db.now())
        return None

    if run["provider"] != "claude":
        set_progress("llm", LLM_START)
        return analyze(run["provider"], meta, report, history=_history(run))

    run = db.get_run(run_id)
    if run["conversation"]:
        conv = json.loads(run["conversation"])
    else:
        conv = _new_conversation(run, meta, report)
        _save(run_id, conv)
    return _converse(run, conv, set_progress, check_cancel, followup_id=None)


def _history(run: dict) -> str:
    if not (run["compare_previous"] and HISTORY_RUNS > 0):
        return ""
    previous = db.previous_runs(run["analysis_id"], run["id"], HISTORY_RUNS)
    if not previous:
        return ""
    db.update_run(run["id"], context_run_ids=json.dumps([r["id"] for r in previous]))
    return build_history(previous, run["created_at"])


def _new_conversation(run: dict, meta: CaptureMeta, report: str) -> dict:
    # The system prompt and tool list must stay fixed for the whole conversation (if they change,
    # the earlier history becomes invalid), so both are stored with the conversation.
    tools_enabled = tools.available()
    return {"tools_enabled": tools_enabled, "system": system_prompt(tools_enabled),
            "messages": [{"role": "user", "content": build_prompt(meta, report, _history(run))}]}


# ---------------------------------------------------------------- follow-up questions
FOLLOWUP_TEMPLATE = """<follow_up_question>
{question}
</follow_up_question>
This is a follow-up question about the capture and the analysis above. Answer it directly and concisely;
you don't need to repeat the full report format.{tool_hint}"""
FOLLOWUP_TOOL_HINT = (" If a tshark command would materially help answer it, you may propose one with "
                      f"{tools.TOOL_NAME} (the user approves it as before).")


def _answer_followup(run: dict, followup_id: int, set_progress, check_cancel) -> None:
    run_id = run["id"]
    followup = db.get_followup(followup_id)
    if run["conversation"]:
        conv = json.loads(run["conversation"])
    else:
        # Runs analyzed before conversations were stored, or parse-only runs: rebuild the start.
        meta = CaptureMeta.model_validate_json(run["metadata"])
        conv = _new_conversation(run, meta, run["report"] or "")
        if run["result"]:
            conv["messages"].append({"role": "assistant", "content": [{"type": "text", "text": run["result"]}]})

    if followup["status"] == "queued":
        hint = FOLLOWUP_TOOL_HINT if conv["tools_enabled"] else ""
        conv["messages"].append({"role": "user",
                                 "content": FOLLOWUP_TEMPLATE.format(question=followup["question"], tool_hint=hint)})
        _save(run_id, conv)
        db.update_followup(followup_id, status="running")

    answer = _converse(db.get_run(run_id), conv, set_progress, check_cancel, followup_id=followup_id)
    _end_followup(run_id, followup_id, status="done", answer=answer)


# ---------------------------------------------------------------- Claude loop + approved commands
def _converse(run: dict, conv: dict, set_progress, check_cancel, *, followup_id: int | None) -> str:
    """Continue the stored conversation until Claude gives a final answer (or pause for approval)."""
    run_id = run["id"]
    if conv["messages"][-1]["role"] == "assistant":
        # Resuming after approval: append the results for the last turn's tool_use blocks.
        conv["messages"].append({"role": "user", "content": _tool_results(run, conv["messages"][-1], set_progress,
                                                                          check_cancel, followup_id)})
        _save(run_id, conv)

    written = {"chars": 0}
    for _ in range(MAX_TURNS):
        check_cancel(force=True)
        base = written["chars"]
        set_progress("llm", LLM_START + int(min(base / EXPECTED_ANSWER_CHARS, 1.0) * (LLM_END - LLM_START)))

        def on_progress(chars: int) -> None:
            written["chars"] = base + chars
            frac = min(written["chars"] / EXPECTED_ANSWER_CHARS, 1.0)
            set_progress("llm_writing", LLM_START + int(frac * (LLM_END - LLM_START)))

        # Conversations stored before `system` was saved fall back to the current prompt.
        msg = claude_turn(conv["messages"], conv["tools_enabled"], on_progress, system=conv.get("system"))
        db.add_usage(run_id, usage_of(msg), followup_id)
        if msg.stop_reason == "refusal":
            raise RuntimeError("Claude declined the request.")
        if msg.stop_reason == "max_tokens":
            # tool input may have been cut off mid-way; running it isn't safe
            raise RuntimeError("Claude's response hit the max_tokens limit.")

        # Assistant content (including thinking blocks) is stored and sent back completely unchanged.
        assistant = {"role": "assistant", "content": msg.to_dict(mode="json")["content"]}
        conv["messages"].append(assistant)
        _save(run_id, conv)

        if msg.stop_reason == "pause_turn":
            continue
        if msg.stop_reason != "tool_use":
            return "".join(b.text for b in msg.content if b.type == "text")

        # Command proposals: stop if any of them need user approval.
        conv["messages"].append({"role": "user", "content": _tool_results(db.get_run(run_id), assistant, set_progress,
                                                                          check_cancel, followup_id)})
        _save(run_id, conv)
    raise RuntimeError(f"Claude did not finish within {MAX_TURNS} turns.")


def _save(run_id: int, conv: dict) -> None:
    db.update_run(run_id, conversation=json.dumps(conv))


def _tool_results(run: dict, assistant: dict, set_progress, check_cancel, followup_id: int | None) -> list[dict]:
    """Produce a tool_result for every tool_use in the assistant message.

    - Registers proposals not seen yet (ones that fail validation or exceed the limit are answered automatically).
    - Auto-approves valid proposals if the analysis is set to; otherwise raises Paused while any proposal
      is waiting for the user's decision.
    - Runs the approved ones.
    Results are returned in tool_use order, in a single user message.
    """
    run_id = run["id"]
    uses = [b for b in assistant["content"] if b.get("type") == "tool_use"]
    known = {c["tool_use_id"]: c for c in db.list_tool_calls(run_id)}
    # the command limit applies separately to the initial analysis and to each follow-up
    used = sum(c["status"] not in ("invalid", "limit") and c["followup_id"] == followup_id for c in known.values())
    auto_approve = bool(db.get_analysis(run["analysis_id"])["auto_approve"])

    for b in uses:
        if b["id"] in known:
            continue
        raw = b.get("input") or {}
        args = raw.get("args") if isinstance(raw.get("args"), list) else []
        purpose = raw.get("purpose") if isinstance(raw.get("purpose"), str) else ""
        if b.get("name") != tools.TOOL_NAME:
            status, out = "invalid", f"Unknown tool: {b.get('name')}"
        elif used >= tools.MAX_TOOL_CALLS:
            status, out = "limit", (f"Command limit ({tools.MAX_TOOL_CALLS}) reached; this command was not run. "
                                    "Don't propose more commands; answer with the data you have.")
        else:
            try:
                tools.parse_input(raw)
                status, out = "pending", None
                used += 1
            except tools.CommandError as e:
                status, out = "invalid", f"Command failed validation and was not run: {e}"
        call_id = db.create_tool_call(run_id, tool_use_id=b["id"], tool=b.get("name", ""), args=args,
                                      purpose=purpose, status=status, output=out, followup_id=followup_id)
        if status == "pending" and auto_approve:
            db.decide_tool_call(call_id, "approved", None, None, decided_by=None)

    calls = {c["tool_use_id"]: c for c in db.list_tool_calls(run_id)}
    if any(calls[b["id"]]["status"] == "pending" for b in uses):
        raise Paused()

    results = []
    approved = [b for b in uses if calls[b["id"]]["status"] == "approved"]
    for b in uses:
        c = calls[b["id"]]
        if c["status"] == "approved":
            check_cancel(force=True)
            set_progress("tool", LLM_START)
            args = json.loads(c["final_args"] or c["args"])
            log.info("run %s: running command (%d/%d): %s", run_id, approved.index(b) + 1, len(approved), args)
            res = tools.run_tshark(db.pcap_file(run["pcap_path"]), args)
            db.update_tool_call(c["id"], status="executed", output=res["output"], exit_code=res["exit_code"],
                                duration=res["duration"], finished_at=db.now())
            c = db.get_tool_call(c["id"])
        results.append(_result_block(b["id"], c, run["pcap_filename"]))
    return results


def _result_block(tool_use_id: str, c: dict, filename: str) -> dict:
    note = f"\nUser note: {c['user_note']}" if c.get("user_note") else ""
    if c["status"] == "executed":
        args = json.loads(c["final_args"] or c["args"])
        head = f"Command run: {tools.display_command(args, filename)}"
        if c["final_args"]:
            head += f"\n(The user edited the command. You proposed: {tools.display_command(json.loads(c['args']), filename)})"
        body = f"{head}{note}\nexit code: {c['exit_code']} · duration: {c['duration']} s\n\n{c['output']}"
        return {"type": "tool_result", "tool_use_id": tool_use_id, "content": body,
                "is_error": c["exit_code"] != 0}
    if c["status"] == "rejected":
        body = ("The user declined to run this command." + note +
                "\nContinue without it, using the data you have.")
    else:  # invalid | limit
        body = c["output"] or "The command was not run."
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": body, "is_error": True}


# ---------------------------------------------------------------- stats backfill
def backfill_stats() -> None:
    """Compute only the stats for older runs (no LLM call)."""
    for run_id in db.runs_missing_stats():
        run = db.get_run(run_id)
        path = db.pcap_file(run["pcap_path"])
        if not path.exists():
            continue
        try:
            meta = CaptureMeta.model_validate_json(run["metadata"])
            with tempfile.TemporaryDirectory() as tmp:
                _, stats = build_report(path, Path(tmp), meta)
            db.update_run(run_id, stats=json.dumps(stats))
            log.info("stats backfilled for run %s", run_id)
        except Exception:  # noqa: BLE001
            log.exception("stats backfill failed for run %s", run_id)


class JobQueue:
    def __init__(self, workers: int):
        self.workers = workers
        self._q: queue.Queue[int | None] = queue.Queue()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        pending = db.recover_pending()
        for run_id in pending:
            self._q.put(run_id)
        for i in range(self.workers):
            t = threading.Thread(target=self._loop, name=f"worker-{i}", daemon=True)
            t.start()
            self._threads.append(t)
        threading.Thread(target=backfill_stats, name="stats-backfill", daemon=True).start()
        log.info("%d workers started, re-queued runs: %d", self.workers, len(pending))

    def submit(self, run_id: int) -> None:
        self._q.put(run_id)

    def stop(self, timeout: float = 5) -> None:
        for _ in self._threads:
            self._q.put(None)
        for t in self._threads:
            t.join(timeout)

    def _loop(self) -> None:
        while (run_id := self._q.get()) is not None:
            process(run_id)
