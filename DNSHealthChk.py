#!/usr/bin/env python3
# dns_trend_probe_live.py
# DNS probe + live Bokeh dashboard (no refresh; streams as results arrive)
# Requires: pip install dnspython bokeh

import argparse
import csv
import datetime as dt
import json
import os
import queue
import socket
import threading
import time
from typing import List, Tuple, Optional, Dict

import dns.resolver
import dns.exception
import dns.rdatatype
import dns.reversename
import dns.flags
import dns.rcode

# ---- Bokeh imports (embedded server) ----
from bokeh.layouts import column, row
from bokeh.models import ColumnDataSource, Select, CheckboxGroup, Div, DatetimeTickFormatter
from bokeh.plotting import figure
from bokeh.server.server import Server

# ----------------------------
# Defaults / Config
# ----------------------------
DEFAULT_INTERVAL = 60
DEFAULT_TIMEOUT = 2.0
DEFAULT_RETRIES = 1

DEFAULT_TARGETS = [
    {"name": "ddc01.yourdomain.local", "type": "A"},
    {"name": "ddc02.yourdomain.local", "type": "A"},
    {"name": "storefront.yourdomain.local", "type": "A"},
    {"name": "cloudconnector01.yourdomain.local", "type": "A"},
    {"name": "_ldap._tcp.yourdomain.local", "type": "SRV"},
    {"name": "_kerberos._tcp.yourdomain.local", "type": "SRV"},
    {"name": "gitlab.yourdomain.local", "type": "A"},
    {"name": "repo.yourdomain.local", "type": "A"}
]

DEFAULT_RESOLVERS = ["system"]

CSV_DIR_DEFAULT = "C:\\temp\\dns_trend" if os.name == "nt" else "/var/log/dns_trend"
ROLLOVER_POINTS = 2000   # how many points to keep in the live chart per resolver
UI_REFRESH_MS = 750      # UI polling interval for the queue

# ----------------------------
# Utilities
# ----------------------------
def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def utc_iso():
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()

def today_csv_path(csv_dir: str) -> str:
    d = dt.datetime.utcnow().strftime("%Y-%m-%d")
    return os.path.join(csv_dir, f"dns_trend_{d}.csv")

def write_header_if_needed(csv_path: str):
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp_utc","resolver","query","type","success","latency_ms",
                "rcode","answers","ttl","used_tcp","error"
            ])

def append_row(csv_path: str, row: dict):
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            row["timestamp_utc"], row["resolver"], row["query"], row["type"],
            1 if row["success"] else 0, row["latency_ms"], row["rcode"],
            row["answers"], row["ttl"], 1 if row["used_tcp"] else 0, row["error"]
        ])

def parse_targets_file(path: Optional[str]) -> List[dict]:
    if not path:
        return list(DEFAULT_TARGETS)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for it in data:
        name = it.get("name")
        rtype = (it.get("type") or "A").upper()
        if name:
            out.append({"name": name, "type": rtype})
    return out

def system_resolver(timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.timeout = timeout
    r.lifetime = timeout
    return r

def custom_resolver(ip: str, timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.timeout = timeout
    r.lifetime = timeout
    r.nameservers = [ip]
    return r

def get_resolvers(entries: List[str], timeout: float) -> List[Tuple[str, dns.resolver.Resolver]]:
    out = []
    for e in entries:
        if e.lower() == "system":
            out.append(("system", system_resolver(timeout)))
        else:
            out.append((e, custom_resolver(e, timeout)))
    return out

def add_local_ptr_if_requested(targets: List[dict], want_ptr: bool):
    if not want_ptr:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        rev = dns.reversename.from_address(ip).to_text(omit_final_dot=True)
        targets.append({"name": rev, "type": "PTR"})
    except Exception:
        pass

def extract_answers(rrsets):
    if not rrsets:
        return ("", None)
    answers = []
    ttl = None
    for rrset in rrsets:
        if getattr(rrset, "ttl", None) is not None:
            ttl = rrset.ttl
        for rdata in rrset:
            answers.append(str(rdata))
    return (", ".join(answers), ttl)

def do_query(resolver: dns.resolver.Resolver, resolver_label: str,
             qname: str, qtype: str, timeout: float, retries: int) -> dict:
    start = time.perf_counter()
    used_tcp = False

    def finalize(success: bool, rcode: str, answers: str, ttl, err: str):
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "timestamp_utc": utc_iso(),
            "resolver": resolver_label,
            "query": qname,
            "type": qtype,
            "success": success,
            "latency_ms": round(latency, 2),
            "rcode": rcode,
            "answers": answers,
            "ttl": ttl,
            "used_tcp": used_tcp,
            "error": err
        }

    try:
        resp = resolver.resolve(qname, qtype, tcp=False, lifetime=timeout)
        ans, ttl = extract_answers(resp.response.answer)
        rc = dns.rcode.to_text(resp.response.rcode())
        if resp.response.flags & dns.flags.TC:
            resp = resolver.resolve(qname, qtype, tcp=True, lifetime=timeout)
            used_tcp = True
            ans, ttl = extract_answers(resp.response.answer)
            rc = dns.rcode.to_text(resp.response.rcode())
        return finalize(True, rc, ans, ttl, "")
    except dns.exception.Timeout:
        try:
            resp = resolver.resolve(qname, qtype, tcp=True, lifetime=timeout)
            used_tcp = True
            ans, ttl = extract_answers(resp.response.answer)
            rc = dns.rcode.to_text(resp.response.rcode())
            return finalize(True, rc, ans, ttl, "")
        except Exception as e2:
            if retries > 0:
                try:
                    resp = resolver.resolve(qname, qtype, tcp=False, lifetime=timeout)
                    ans, ttl = extract_answers(resp.response.answer)
                    rc = dns.rcode.to_text(resp.response.rcode())
                    return finalize(True, rc, ans, ttl, "")
                except Exception as e3:
                    return finalize(False, "TIMEOUT", "", None, f"{type(e3).__name__}: {e3}")
            return finalize(False, "TIMEOUT", "", None, "Timeout after UDP and TCP")
    except Exception as e:
        rc = "ERROR"
        try:
            if hasattr(e, "responses") and e.responses:
                rc = dns.rcode.to_text(e.responses[0].rcode())
        except Exception:
            pass
        return finalize(False, rc, "", None, f"{type(e).__name__}: {e}")

# ----------------------------
# Probe thread
# ----------------------------
def probe_loop(args, targets, resolvers, out_queue: queue.Queue):
    while True:
        csv_path = today_csv_path(args.csv_dir)
        write_header_if_needed(csv_path)

        for t in targets:
            qname = t["name"]
            qtype = t.get("type", "A").upper()
            for label, r in resolvers:
                row = do_query(r, label, qname, qtype, args.timeout, args.retries)
                append_row(csv_path, row)
                # push to UI
                out_queue.put(row)
                time.sleep(0.03)  # tiny spacing
        time.sleep(args.interval + (os.getpid() % 5) * 0.05)

# ----------------------------
# Bokeh app
# ----------------------------
def make_bokeh_app(out_queue: queue.Queue, resolvers: List[Tuple[str, dns.resolver.Resolver]], targets: List[dict]):
    # One CDS per resolver, so each gets its own line (less clutter).
    sources: Dict[str, ColumnDataSource] = {}
    success_sources: Dict[str, ColumnDataSource] = {}
    for label, _ in resolvers:
        sources[label] = ColumnDataSource(dict(ts=[], latency=[], resolver=[], qname=[], qtype=[], success=[]))
        success_sources[label] = ColumnDataSource(dict(ts=[], value=[]))  # 1/0 success sparkline

    resolver_labels = [r[0] for r in resolvers]
    target_names = [f"{t['name']} ({t['type']})" for t in targets]

    # Controls
    resolver_filter = CheckboxGroup(labels=resolver_labels, active=list(range(len(resolver_labels))))
    target_select = Select(title="Filter by target (optional):",
                           value="All",
                           options=["All"] + target_names)

    # Latency plot
    p = figure(title="DNS Latency (ms) by Resolver",
               x_axis_type="datetime", height=400, sizing_mode="stretch_width",
               toolbar_location="right")
    p.yaxis.axis_label = "Latency (ms)"
    p.xaxis.formatter = DatetimeTickFormatter(seconds="%H:%M:%S", minutes="%H:%M", hours="%H:%M", days="%m/%d")

    # Success plot (0/1)
    s = figure(title="Success (1) / Failure (0) by Resolver",
               x_axis_type="datetime", height=200, sizing_mode="stretch_width",
               toolbar_location="right")
    s.yaxis.axis_label = "Success"
    s.y_range.start = -0.1
    s.y_range.end = 1.1
    s.xaxis.formatter = DatetimeTickFormatter(seconds="%H:%M:%S", minutes="%H:%M", hours="%H:%M", days="%m/%d")

    # Add a line per resolver
    for label in resolver_labels:
        p.line(source=sources[label], x="ts", y="latency", legend_label=label, line_width=2, muted_alpha=0.15)
        s.step(source=success_sources[label], x="ts", y="value", legend_label=label, line_width=2, mode="after", muted_alpha=0.15)

    p.legend.click_policy = "mute"
    s.legend.click_policy = "mute"

    header = Div(text="""
        <h2 style="margin:0">DNS Live Monitor</h2>
        <p style="margin:6px 0 0 0">Streams results from the on-host probe. Use the checkboxes to hide/show resolvers and the dropdown to filter to a specific target.</p>
    """, sizing_mode="stretch_width")

    layout = column(header, row(resolver_filter, target_select), p, s, sizing_mode="stretch_both")

    # State for filter
    def passes_filter(row: dict) -> bool:
        # Resolver visible?
        active_resolvers = {resolver_labels[i] for i in resolver_filter.active}
        if row["resolver"] not in active_resolvers:
            return False
        # Target filter?
        if target_select.value != "All":
            want = target_select.value
            if want != f"{row['query']} ({row['type']})":
                return False
        return True

    # Periodic callback: drain queue, stream to CDS
    def update():
        drained = 0
        while True:
            try:
                row = out_queue.get_nowait()
            except queue.Empty:
                break
            drained += 1
            # apply filter for plotting only; CSV persists regardless
            if not passes_filter(row):
                continue
            ts = dt.datetime.fromisoformat(row["timestamp_utc"].replace("Z", "+00:00"))
            lbl = row["resolver"]
            ok = 1 if row["success"] else 0
            sources[lbl].stream({
                "ts": [ts],
                "latency": [row["latency_ms"]],
                "resolver": [lbl],
                "qname": [row["query"]],
                "qtype": [row["type"]],
                "success": [ok],
            }, rollover=ROLLOVER_POINTS)
            success_sources[lbl].stream({
                "ts": [ts],
                "value": [ok],
            }, rollover=ROLLOVER_POINTS)
        # nothing else; Bokeh handles re-render

    return layout, update

# ----------------------------
# Orchestration
# ----------------------------
def run(args):
    ensure_dir(args.csv_dir)
    targets = parse_targets_file(args.targets_file)
    add_local_ptr_if_requested(targets, args.probe_local_ptr)
    resolvers = get_resolvers(args.resolvers, args.timeout)

    # Shared queue for probe -> UI
    out_queue: queue.Queue = queue.Queue(maxsize=5000)

    # Start probe in background thread
    t = threading.Thread(target=probe_loop, args=(args, targets, resolvers, out_queue), daemon=True)
    t.start()

    # Start Bokeh server
    def bk_app(doc):
        layout, update_fn = make_bokeh_app(out_queue, resolvers, targets)
        doc.add_root(layout)
        doc.add_periodic_callback(update_fn, UI_REFRESH_MS)

    server = Server({"/dns": bk_app}, port=args.bokeh_port, allow_websocket_origin=[f"localhost:{args.bokeh_port}", f"127.0.0.1:{args.bokeh_port}"])
    print(f"[INFO] Bokeh live dashboard: http://localhost:{args.bokeh_port}/dns")
    server.start()
    server.io_loop.start()

def main():
    ap = argparse.ArgumentParser(description="DNS probe with live Bokeh dashboard (streams without refresh)")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Seconds between probe rounds (default 60)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-query timeout seconds (default 2.0)")
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retries per query (default 1)")
    ap.add_argument("--resolvers", nargs="+", default=DEFAULT_RESOLVERS, help='Resolvers to test (e.g., system 10.10.0.10 10.10.0.11)')
    ap.add_argument("--targets-file", type=str, help='JSON file: [{"name":"fqdn","type":"A|AAAA|SRV|PTR|CNAME"}]')
    ap.add_argument("--probe-local-ptr", action="store_true", help="Also probe PTR of local primary IPv4")
    ap.add_argument("--csv-dir", type=str, default=CSV_DIR_DEFAULT, help="Directory for daily CSVs")
    ap.add_argument("--bokeh-port", type=int, default=5006, help="Port for the Bokeh server (default 5006)")
    args = ap.parse_args()

    try:
        run(args)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped.")

if __name__ == "__main__":
    main()
