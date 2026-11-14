"""Additional analysis commands the LLM can run with user approval (currently: tshark).

Safety:
- No shell; arguments are passed to subprocess as a list.
- `-r <pcap>` is added by the system; the model cannot choose the file.
- Only allowlisted flags are accepted (options that write files, capture live traffic or run
  Lua are not on the list). Combined flags (like -nqw) are rejected.
- Run time and output size are capped.
"""
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

TOOL_NAME = "run_tshark"
MAX_TOOL_CALLS = int(os.getenv("MAX_TOOL_CALLS", "5"))  # per run
TIMEOUT_SECONDS = int(os.getenv("TOOL_TIMEOUT_SECONDS", "120"))
MAX_OUTPUT_CHARS = int(os.getenv("TOOL_MAX_OUTPUT_CHARS", "20000"))

# flags that take a value → the next argument is the value
FLAGS_WITH_VALUE = {
    "-Y",  # display filter
    "-R",  # read filter (2-pass)
    "-T",  # output format
    "-e",  # field
    "-E",  # field output options
    "-z",  # statistics
    "-t",  # time format
    "-O",  # show details only for these protocols
    "-c",  # packet count limit
    "-d",  # decode as (e.g. udp.port==8472,vxlan)
    "-j", "-J",  # JSON filters
}
FLAGS_NO_VALUE = {"-2", "-q", "-n", "-V", "-x", "-l", "-P", "-S", "-Q", "--no-duplicate-keys"}
T_FORMATS = {"fields", "json", "jsonraw", "ek", "text", "tabs", "pdml", "psml"}
BLOCKED_Z_PREFIXES = ("follow,",)  # follow output can be huge; narrow it down with -Y instead


class ToolInput(BaseModel):
    args: list[str] = Field(min_length=1, max_length=60)
    purpose: str = Field(min_length=3, max_length=1000)


TOOL_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "Runs tshark on the pcap file the user uploaded and returns its output. "
        "Every call is shown to the user before it runs; the user can approve, edit or reject it. "
        "Use it only when the existing summary isn't enough to answer a question and the command's result "
        "could concretely change your assessment. "
        "Do NOT add `-r` or a file path; the system adds them. Allowed flags: "
        "-Y -R -2 -T -e -E -z -t -O -c -d -j -J -q -n -V -x -l -P -S -Q. "
        "Options that write files, capture live traffic or run scripts are rejected. "
        "Keep the output small: filter with -Y, take only the needed fields with -T fields -e, and cap with -c if needed. "
        f"Output longer than {MAX_OUTPUT_CHARS} characters is clipped."
    ),
    "eager_input_streaming": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": 'tshark arguments, one per element. E.g.: ["-Y", "dns.flags.response == 0", '
                               '"-T", "fields", "-e", "frame.time_relative", "-e", "ip.dst", "-e", "dns.qry.name"]',
            },
            "purpose": {
                "type": "string",
                "description": "Short explanation shown to the user: what this command will extract/verify "
                               "and how its result could affect the assessment.",
            },
        },
        "required": ["args", "purpose"],
        "additionalProperties": False,
    },
}


class CommandError(ValueError):
    pass


def available() -> bool:
    return shutil.which("tshark") is not None


def parse_input(raw: dict) -> ToolInput:
    """Validate model output against the schema (the API doesn't validate with eager streaming)."""
    try:
        inp = ToolInput.model_validate(raw)
    except ValidationError as e:
        raise CommandError(f"invalid tool input: {e.errors()[0]['msg']}") from e
    validate_args(inp.args)
    return inp


def validate_args(args: list[str]) -> None:
    i = 0
    while i < len(args):
        a = args[i]
        if not isinstance(a, str) or "\x00" in a:
            raise CommandError("invalid argument")
        if a in FLAGS_NO_VALUE:
            i += 1
            continue
        if a in FLAGS_WITH_VALUE:
            if i + 1 >= len(args):
                raise CommandError(f"{a} expects a value")
            val = args[i + 1]
            if a == "-T" and val not in T_FORMATS:
                raise CommandError(f"allowed formats for -T: {', '.join(sorted(T_FORMATS))}")
            if a == "-z" and val.startswith(BLOCKED_Z_PREFIXES):
                raise CommandError("-z follow is not supported; filter the stream with -Y and use -T fields")
            if a == "-c" and not val.isdigit():
                raise CommandError("-c expects a number")
            i += 2
            continue
        if a.startswith("-"):
            raise CommandError(f"flag not allowed: {a}")
        raise CommandError(f"unexpected argument: {a!r} (values must follow a flag)")


def display_command(args: list[str], filename: str) -> str:
    return shlex.join(["tshark", "-r", filename, *args])


def split_command(text: str) -> list[str]:
    """User-edited command line → argument list (a leading 'tshark -r file' is stripped)."""
    try:
        parts = shlex.split(text)
    except ValueError as e:
        raise CommandError(f"could not parse command: {e}") from e
    if parts[:1] == ["tshark"]:
        parts = parts[1:]
    if len(parts) >= 2 and parts[0] == "-r":
        parts = parts[2:]
    return parts


def _clip(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    head, tail = int(MAX_OUTPUT_CHARS * 0.75), int(MAX_OUTPUT_CHARS * 0.25)
    return f"{text[:head]}\n... ({len(text) - head - tail} characters clipped) ...\n{text[-tail:]}"


def run_tshark(pcap: Path, args: list[str]) -> dict:
    """Run the command. Returns {output, exit_code, duration}. Arguments are re-validated here."""
    validate_args(args)
    if not available():
        return {"output": "tshark not found (macOS: brew install wireshark).", "exit_code": -1, "duration": 0.0}
    started = time.monotonic()
    try:
        res = subprocess.run(["tshark", "-r", str(pcap), *args], capture_output=True, text=True,
                             timeout=TIMEOUT_SECONDS, stdin=subprocess.DEVNULL)
        out = res.stdout
        if res.stderr.strip():
            out += f"\n[stderr]\n{res.stderr.strip()[:2000]}"
        code = res.returncode
    except subprocess.TimeoutExpired:
        out, code = f"Command did not finish within {TIMEOUT_SECONDS} seconds and was stopped.", -1
    return {"output": _clip(out.strip() or "(no output)"), "exit_code": code,
            "duration": round(time.monotonic() - started, 2)}
