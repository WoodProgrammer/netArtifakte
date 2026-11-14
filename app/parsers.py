"""Step 2: parse the pcap with zeek and tshark.

Produces two outputs:
- a compact text report sent to the LLM
- structured statistics for drawing charts in the UI (stats, JSON)
"""
import json
import math
import shutil
import statistics
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable

from .models import CaptureMeta

TOP_N = 15
CHART_TOP_N = 8
MAX_DNS_POINTS = 500
MAX_TIMELINE_BINS = 60
NICE_BUCKETS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 86400]
DNS_ERROR_RCODES = {"SERVFAIL", "REFUSED", "NOTIMP", "FORMERR"}


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {res.stderr.strip()[:500]}")
    return res.stdout


def _read_zeek_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _p95(values: list[float]) -> float:
    v = sorted(values)
    return v[max(math.ceil(len(v) * 0.95) - 1, 0)]


def _ms(seconds: float | None) -> float | None:
    return None if seconds is None else round(seconds * 1000, 2)


def _conn_bytes(c: dict) -> int:
    return (c.get("orig_ip_bytes") or 0) + (c.get("resp_ip_bytes") or 0)


def _conn_pkts(c: dict) -> int:
    return (c.get("orig_pkts") or 0) + (c.get("resp_pkts") or 0)


def _dns_unanswered(d: dict) -> bool:
    return not d.get("rcode_name")


# ---------------------------------------------------------------- Zeek istatistikleri
def _timeline(conns: list[dict], dns: list[dict]) -> dict | None:
    starts = [c["ts"] for c in conns] + [d["ts"] for d in dns]
    if not starts:
        return None
    start = min(starts)
    end = max([c["ts"] + (c.get("duration") or 0) for c in conns] + starts)
    span = max(end - start, 1)
    bucket = next((b for b in NICE_BUCKETS if span / b <= MAX_TIMELINE_BINS), NICE_BUCKETS[-1])
    n = int(span // bucket) + 1
    pts = [{"t": start + i * bucket, "connections": 0, "bytes": 0, "packets": 0,
            "dns_queries": 0, "dns_unanswered": 0} for i in range(n)]
    for c in conns:
        p = pts[min(int((c["ts"] - start) // bucket), n - 1)]
        p["connections"] += 1
        p["bytes"] += _conn_bytes(c)
        p["packets"] += _conn_pkts(c)
    for d in dns:
        p = pts[min(int((d["ts"] - start) // bucket), n - 1)]
        p["dns_queries"] += 1
        p["dns_unanswered"] += _dns_unanswered(d)
    return {"start": start, "end": end, "bucket_seconds": bucket, "points": pts}


def _top_talkers(conns: list[dict], meta: CaptureMeta) -> list[dict]:
    bytes_, count = Counter(), Counter()
    for c in conns:
        b = _conn_bytes(c)
        for ip in {c["id.orig_h"], c["id.resp_h"]}:
            bytes_[ip] += b
            count[ip] += 1
    return [{"ip": ip, "label": meta.label(ip), "bytes": b, "connections": count[ip]}
            for ip, b in bytes_.most_common(CHART_TOP_N)]


def _top_ports(conns: list[dict]) -> list[dict]:
    ports = Counter((c["id.resp_p"], c.get("proto", "?")) for c in conns)
    return [{"port": p, "proto": proto, "connections": n} for (p, proto), n in ports.most_common(CHART_TOP_N)]


def _dns_stats(dns: list[dict], meta: CaptureMeta) -> dict:
    servers = defaultdict(lambda: {"queries": 0, "answered": 0, "rtts": []})
    domains = defaultdict(lambda: {"count": 0, "unanswered": 0})
    queries = []
    for d in sorted(dns, key=lambda x: x["ts"]):
        srv = servers[d["id.resp_h"]]
        srv["queries"] += 1
        unanswered = _dns_unanswered(d)
        if not unanswered:
            srv["answered"] += 1
        if d.get("rtt"):
            srv["rtts"].append(d["rtt"])
        name = d.get("query") or "-"
        domains[name]["count"] += 1
        domains[name]["unanswered"] += unanswered
        if len(queries) < MAX_DNS_POINTS:
            queries.append({"t": d["ts"], "query": name, "qtype": d.get("qtype_name"),
                            "server": meta.label(d["id.resp_h"]), "rtt_ms": _ms(d.get("rtt")),
                            "rcode": d.get("rcode_name") or "NO_RESPONSE"})
    return {
        "rcodes": dict(Counter(d.get("rcode_name") or "NO_RESPONSE" for d in dns)),
        "servers": sorted(
            ({"ip": ip, "label": meta.label(ip), "queries": s["queries"], "answered": s["answered"],
              "avg_rtt_ms": _ms(statistics.mean(s["rtts"])) if s["rtts"] else None}
             for ip, s in servers.items()),
            key=lambda s: -s["queries"]),
        "top_domains": [{"name": n, **v} for n, v in
                        sorted(domains.items(), key=lambda kv: -kv[1]["count"])[:CHART_TOP_N]],
        "queries": queries,
        "queries_truncated": len(dns) > MAX_DNS_POINTS,
    }


# ---------------------------------------------------------------- Zeek
def zeek_summary(pcap: Path, workdir: Path, meta: CaptureMeta) -> tuple[str, dict]:
    if not shutil.which("zeek"):
        return "zeek not found, skipped.", {}
    zdir = workdir / "zeek"
    zdir.mkdir()
    # -C: ignore checksum errors (common because of NIC offload)
    _run(["zeek", "-C", "-r", str(pcap.resolve()), "LogAscii::use_json=T"], cwd=zdir)

    conns = _read_zeek_log(zdir / "conn.log")
    weird = _read_zeek_log(zdir / "weird.log")
    tunnels = _read_zeek_log(zdir / "tunnel.log")
    dns = _read_zeek_log(zdir / "dns.log")

    states = Counter(c.get("conn_state") or "-" for c in conns)
    # t/T in history = retransmission
    retrans = [c for c in conns if any(x in c.get("history", "") for x in "tT")]

    out = [f"Total connections: {len(conns)}",
           "conn_state distribution: " + json.dumps(states),
           f"Connections with retransmissions: {len(retrans)}"]

    def fmt(c: dict) -> str:
        return (f"{meta.label(c['id.orig_h'])}:{c['id.orig_p']} -> "
                f"{meta.label(c['id.resp_h'])}:{c['id.resp_p']} {c.get('proto')} "
                f"svc={c.get('service', '-')} dur={c.get('duration', 0):.3f}s "
                f"state={c.get('conn_state')} history={c.get('history', '')}")

    longest = sorted(conns, key=lambda c: c.get("duration") or 0, reverse=True)[:TOP_N]
    out.append(f"\nLongest {len(longest)} connections (out of {len(conns)}):")
    out += ["  " + fmt(c) for c in longest]
    if retrans:
        out.append(f"\nConnections with retransmissions (first {min(TOP_N, len(retrans))} / {len(retrans)}):")
        out += ["  " + fmt(c) for c in retrans[:TOP_N]]
    if weird:
        out.append("\nZeek weird events: " + json.dumps(Counter(w.get("name") for w in weird)))
    if tunnels:
        out.append("Tunnel (VXLAN/Geneve etc.) detected: "
                   + json.dumps(Counter(t.get("tunnel_type") for t in tunnels)))

    rtts = [d["rtt"] for d in dns if d.get("rtt")]
    if dns:
        out.append(f"\nDNS queries: {len(dns)}, rcode: "
                   + json.dumps(Counter(d.get("rcode_name", "NO_RESPONSE") for d in dns)))
        if rtts:
            out.append(f"DNS RTT ort={statistics.mean(rtts)*1000:.1f}ms max={max(rtts)*1000:.1f}ms")

    stats = {
        "timeline": _timeline(conns, dns),
        "totals": {
            "connections": len(conns),
            "bytes": sum(_conn_bytes(c) for c in conns),
            "packets": sum(_conn_pkts(c) for c in conns),
            "retrans_connections": len(retrans),
            "weird": len(weird),
            "dns_queries": len(dns),
            "dns_unanswered": sum(_dns_unanswered(d) for d in dns),
            "dns_errors": sum((d.get("rcode_name") in DNS_ERROR_RCODES) for d in dns),
            "dns_rtt_avg_ms": _ms(statistics.mean(rtts)) if rtts else None,
            "dns_rtt_p95_ms": _ms(_p95(rtts)) if rtts else None,
        },
        "conn_states": dict(states.most_common()),
        "protocols": dict(Counter(c.get("proto") or "-" for c in conns).most_common()),
        "services": dict(Counter(c.get("service") or "-" for c in conns).most_common()),
        "top_talkers": _top_talkers(conns, meta),
        "top_ports": _top_ports(conns),
        "weird": dict(Counter(w.get("name") for w in weird).most_common()),
        "tunnels": dict(Counter(t.get("tunnel_type") for t in tunnels).most_common()),
        "dns": _dns_stats(dns, meta) if dns else None,
    }
    return "\n".join(out), stats


# ---------------------------------------------------------------- tshark
def _last(v: str) -> str:
    # In an encapsulated (VXLAN) packet ip.src is "outer,inner"; take the inner header.
    return v.split(",")[-1]


def tshark_summary(pcap: Path, meta: CaptureMeta) -> tuple[str, dict]:
    if not shutil.which("tshark"):
        return "tshark not found, skipped (macOS: brew install wireshark).", {}
    p = str(pcap)
    out = []

    # 1) Per-flow ACK RTT statistics
    rows = _run(["tshark", "-r", p, "-Y", "tcp.analysis.ack_rtt", "-T", "fields",
                 "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.analysis.ack_rtt"])
    rtt = defaultdict(list)
    for line in rows.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2]:
            rtt[(_last(parts[0]), _last(parts[1]))].append(float(_last(parts[2])))
    ranked = sorted(rtt.items(), key=lambda kv: statistics.mean(kv[1]), reverse=True)
    rtt_flows = []
    for (s, d), v in ranked[:TOP_N]:
        v.sort()
        rtt_flows.append({"src": meta.label(s), "dst": meta.label(d), "n": len(v),
                          "avg_ms": _ms(statistics.mean(v)), "p95_ms": _ms(_p95(v)), "max_ms": _ms(v[-1])})
    if rtt_flows:
        out.append("TCP ACK RTT (per flow, ms) — highest averages:")
        out += [f"  {f['src']} -> {f['dst']} n={f['n']} avg={f['avg_ms']:.2f} "
                f"p95={f['p95_ms']:.2f} max={f['max_ms']:.2f}" for f in rtt_flows]
        if len(ranked) > TOP_N:
            out.append(f"  (showing first {TOP_N} of {len(ranked)} flows)")

    # 2) TCP problem flags
    rows = _run(["tshark", "-r", p, "-Y", "tcp.analysis.flags && !tcp.analysis.window_update",
                 "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.expert.message"])
    issues, by_type = Counter(), Counter()
    for line in rows.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            issues[(meta.label(_last(parts[0])), meta.label(_last(parts[1])), parts[2])] += 1
            by_type[parts[2]] += 1
    if issues:
        out.append("\nTCP analysis warnings (source -> destination: message = count):")
        for (s, d, m), n in issues.most_common(TOP_N * 2):
            out.append(f"  {s} -> {d}: {m} = {n}")

    # 3) Overall protocol hierarchy
    out.append("\nProtocol hierarchy:")
    out.append(_run(["tshark", "-r", p, "-q", "-z", "io,phs"]).strip())

    stats = {"tcp": {"rtt_flows": rtt_flows, "issues": dict(by_type.most_common(CHART_TOP_N)),
                     "issue_total": sum(by_type.values())}}
    return "\n".join(out), stats


def build_report(pcap: Path, workdir: Path, meta: CaptureMeta,
                 on_stage: Callable[[str, int], None] | None = None) -> tuple[str, dict]:
    """Return (text report for the LLM, stats for charts).

    on_stage(stage, progress%) — lets the worker write progress to the DB.
    """
    notify = on_stage or (lambda *_: None)
    notify("zeek", 10)
    zeek_text, zeek_stats = zeek_summary(pcap, workdir, meta)
    notify("tshark", 40)
    tshark_text, tshark_stats = tshark_summary(pcap, meta)
    stats = {**zeek_stats, **tshark_stats,
             "tools": {"zeek": bool(zeek_stats), "tshark": bool(tshark_stats)}}
    return f"=== ZEEK ===\n{zeek_text}\n\n=== TSHARK ===\n{tshark_text}", stats
