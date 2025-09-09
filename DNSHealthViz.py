#!/usr/bin/env python3
# DNSHealthViz_console.py — live console DNS dashboard (route-aware + per-series thresholds)
# Stdlib only. Reads today's CSV from DNSHealthChk and renders a rolling, well-aligned table.
# Features:
#   - --group-by-route: aggregate per resolver [src->dst] if src_ip/dst_ip present
#   - --group-by-target: one line per resolver/target
#   - Per-series threshold rules (--rule / --rules-file)
#   - Polished columns: fixed widths, right-aligned numerics, stable unit formatting
#   - Timezone-safe (UTC-aware) timestamps
#   - Backward compatible with CSVs without src_ip/dst_ip

import argparse, csv, datetime as dt, os, time, collections, math, sys, json, re

DATEFMT = "%Y-%m-%d"

# --- Global defaults (can be overridden per-series by rules) ---
GLOBAL_THRESH_OK = 95.0    # percent
GLOBAL_THRESH_P95 = 10.0   # ms

# --- Column widths ---
KEY_W  = 60
N_W    = 5
OK_W   = 7   # e.g., '100.0%' fits
P50_W  = 8
P95_W  = 8
LAST_W = 8
AGE_W  = 6   # '123s'
THR_W  = 3   # '*' marker
MEAN_W = 8

# --- ANSI color helpers ---
def color(s, code): return f"\033[{code}m{s}\033[0m"
def red(s): return color(s, "31")
def yellow(s): return color(s, "33")
def green(s): return color(s, "32")

def latest_csv(csv_dir: str) -> str:
    return os.path.join(csv_dir, f"dns_trend_{dt.datetime.now(dt.timezone.utc).strftime(DATEFMT)}.csv")

def tail_csv(path: str, start_pos: int):
    """Return (new_pos, [new_lines]) from CSV starting at byte offset start_pos."""
    if not os.path.exists(path):
        return start_pos, []
    with open(path, "r", encoding="utf-8") as f:
        f.seek(start_pos)
        lines = f.readlines()
        new_pos = f.tell()
    rows = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        if start_pos == 0 and i == 0 and line.lower().startswith("timestamp_utc"):
            # header
            continue
        rows.append(line)
    return new_pos, rows

def parse_ts(ts_iso: str) -> dt.datetime:
    try:
        ts = dt.datetime.fromisoformat(ts_iso.replace("Z","+00:00"))
    except Exception:
        ts = dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts

def parse_row(line: str):
    # CSV columns (first 11 are fixed):
    # timestamp_utc,resolver,query,type,success,latency_ms,rcode,answers,ttl,used_tcp,error
    r = next(csv.reader([line]))
    while len(r) < 11:
        r.append("")
    ts_iso, resolver, qname, rtype, success, latency_ms, rcode, answers, ttl, used_tcp, err = r[:11]

    # optional extra columns (new collector adds src_ip,dst_ip at 12/13)
    src_ip = r[11] if len(r) > 11 else ""
    dst_ip = r[12] if len(r) > 12 else ""

    ts = parse_ts(ts_iso)
    try:
        lat = float(latency_ms)
    except Exception:
        lat = math.nan
    ok = (rcode == "NOERROR") and (success in ("1", "True", "true"))
    return ts, resolver, qname, rtype, ok, lat, rcode, src_ip, dst_ip

def clear_console():
    os.system("cls" if os.name == "nt" else "clear")

# Fixed-width latency formatting: keep column width stable regardless of 'ms'/'s'
def fmt_ms_fixed(x, width):
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return f"{'—':>{width}}"
    if x < 1000:
        # integer ms
        return f"{int(round(x)):>{width-2}}ms"
    # seconds with 2 decimals
    return f"{x/1000:>{width-1}.2f}s"

def fmt_pct_fixed(x, width):
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return f"{'—':>{width}}"
    return f"{x:>{width-1}.1f}%"

def percentile(arr, p):
    if not arr:
        return None
    a = sorted(arr)
    k = max(0, min(len(a)-1, int(round((p/100.0)*(len(a)-1)))))
    return a[k]

def compile_rules(inline_rules, rules_file):
    """Return list of rules: [{'regex': compiled, 'ok': float or None, 'p95': float or None, 'raw': str}]"""
    rules = []
    # file rules (JSON array of {pattern, ok_pct?, p95_ms?})
    if rules_file:
        with open(rules_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        for obj in data:
            pat = obj.get("pattern", "")
            ok = obj.get("ok_pct", None)
            p95 = obj.get("p95_ms", None)
            if not pat or (ok is None and p95 is None):
                continue
            try:
                rx = re.compile(pat)
                rules.append({"regex": rx, "ok": ok, "p95": p95, "raw": pat})
            except re.error:
                pass
    # inline rules: --rule "pattern=<regex>; ok=95; p95=8"
    for raw in inline_rules or []:
        pat, ok, p95 = None, None, None
        parts = [p.strip() for p in re.split(r"[;,]", raw) if p.strip()]
        for p in parts:
            if p.lower().startswith("pattern="):
                pat = p.split("=",1)[1].strip()
            elif p.lower().startswith("ok=") or p.lower().startswith("ok_pct="):
                try: ok = float(p.split("=",1)[1].strip())
                except: pass
            elif p.lower().startswith("p95=") or p.lower().startswith("p95_ms="):
                try: p95 = float(p.split("=",1)[1].strip())
                except: pass
        if pat and (ok is not None or p95 is not None):
            try:
                rx = re.compile(pat)
                rules.append({"regex": rx, "ok": ok, "p95": p95, "raw": pat})
            except re.error:
                pass
    return rules

def main():
    ap = argparse.ArgumentParser(description="Console DNS dashboard (route-aware, per-series thresholds, aligned)")
    ap.add_argument("--csv-dir", required=True, help="Directory where DNSHealthChk writes CSVs (e.g., ~/DNS/logs)")
    ap.add_argument("--window", type=int, default=300, help="Rolling points per series (default 300)")
    ap.add_argument("--group-by-target", action="store_true",
                    help="If set, show one line per resolver+target. Default aggregates per resolver.")
    ap.add_argument("--group-by-route", action="store_true",
                    help="If set, show one line per resolver [src->dst] route (requires src_ip/dst_ip in CSV).")
    ap.add_argument("--refresh", type=float, default=2.0, help="Seconds between screen refresh (default 2s)")
    ap.add_argument("--show-mean", action="store_true", help="Also show mean latency (last column)")
    # per-series rules
    ap.add_argument("--rule", action="append",
                    help='Threshold rule, e.g.: --rule "pattern=.*_ldap\\._tcp.*; ok=90; p95=15" (repeatable)')
    ap.add_argument("--rules-file", type=str,
                    help='JSON file with [{"pattern":"<regex>","ok_pct":95,"p95_ms":10}, ...]')
    # global overrides (optional)
    ap.add_argument("--ok-thresh", type=float, default=GLOBAL_THRESH_OK, help="Global OK%% threshold (default 95)")
    ap.add_argument("--p95-thresh", type=float, default=GLOBAL_THRESH_P95, help="Global p95 threshold ms (default 10)")
    args = ap.parse_args()

    rules = compile_rules(args.rule, args.rules_file)

    current_day = dt.datetime.now(dt.timezone.utc).strftime(DATEFMT)
    csv_path = latest_csv(args.csv_dir)
    file_pos = 0

    # series buffers: key -> deque of (ts(aware UTC), ok(0/1), latency_ms)
    series = collections.defaultdict(lambda: collections.deque(maxlen=args.window))
    last_ts = {}   # last-seen timestamp per key
    meta = {}      # key -> dict(resolver, qname, rtype, src, dst, ctx)

    def build_context(resolver, qname, rtype, src, dst):
        target = f"{qname} ({rtype})"
        route = f"{src}->{dst}" if (src or dst) else "n/a"
        return f"{resolver} {target} {route}"

    def key_of(resolver, qname, rtype, src_ip="", dst_ip=""):
        if args.group_by_target:
            return (resolver, f"{qname} ({rtype})")
        if args.group_by_route:
            route = f"{src_ip}->{dst_ip}" if (src_ip or dst_ip) else "n/a"
            return f"{resolver} [{route}]"
        return resolver  # default aggregate per resolver

    def apply_thresholds_for(key):
        """Return (ok_thresh, p95_thresh, matched_rule_str_or_None)."""
        m = meta.get(key)
        if not m or not rules:
            return args.ok_thresh, args.p95_thresh, None
        ctx = m["ctx"]
        for rule in rules:  # first match wins
            if rule["regex"].search(ctx):
                okv  = rule["ok"]  if rule["ok"]  is not None else args.ok_thresh
                p95v = rule["p95"] if rule["p95"] is not None else args.p95_thresh
                return okv, p95v, rule["raw"]
        return args.ok_thresh, args.p95_thresh, None

    def roll_if_new_day():
        nonlocal current_day, csv_path, file_pos
        today = dt.datetime.now(dt.timezone.utc).strftime(DATEFMT)
        if today != current_day:
            current_day = today
            csv_path = latest_csv(args.csv_dir)
            file_pos = 0

    def ingest(lines):
        for line in lines:
            ts, resolver, qname, rtype, ok, lat, rcode, src_ip, dst_ip = parse_row(line)
            k = key_of(resolver, qname, rtype, src_ip, dst_ip)
            series[k].append((ts, 1 if ok else 0, lat))
            last_ts[k] = ts
            if k not in meta:
                ctx = build_context(resolver, qname, rtype, src_ip, dst_ip)
                meta[k] = dict(resolver=resolver, qname=qname, rtype=rtype, src=src_ip, dst=dst_ip, ctx=ctx)

    def summarize():
        rows = []
        now = dt.datetime.now(dt.timezone.utc)
        for k, dq in series.items():
            if not dq:
                continue
            oks  = [v[1] for v in dq]
            lats = [v[2] for v in dq if not math.isnan(v[2])]
            cnt = len(dq)
            ok_rate = (sum(oks)/cnt)*100.0
            p50 = percentile(lats, 50) if lats else None
            p95 = percentile(lats, 95) if lats else None
            mean = (sum(lats)/len(lats)) if lats else None
            last_latency = next((v[2] for v in reversed(dq) if not math.isnan(v[2])), math.nan)
            age_s = (now - last_ts.get(k, now)).total_seconds()
            ok_thr, p95_thr, rule_raw = apply_thresholds_for(k)
            rows.append({
                "key": k, "count": cnt, "ok_rate": ok_rate, "p50": p50, "p95": p95,
                "mean": mean, "last": last_latency, "age": age_s,
                "ok_thr": ok_thr, "p95_thr": p95_thr, "rule": rule_raw
            })
        # sort: lowest OK% first, then highest p95
        rows.sort(key=lambda r: (r["ok_rate"], -(r["p95"] if r["p95"] is not None else -1)))
        return rows

    while True:
        roll_if_new_day()
        file_pos, lines = tail_csv(csv_path, file_pos)
        if lines:
            ingest(lines)

        clear_console()
        # Header / banner
        print(f"DNSHealthViz (console, route-aware, rules) | Source: {csv_path}")
        print("Window:", args.window, "points  Refresh:", args.refresh, "s  UTC:",
              dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        mode = "resolver"
        if args.group_by_target: mode = "resolver+target"
        elif args.group_by_route: mode = "resolver [src->dst]"
        print(f"Grouping: {mode}")
        if rules: print(f"Rules: {len(rules)} loaded (first match wins)")

        # Table header
        sep = "-" * (KEY_W + N_W + OK_W + P50_W + P95_W + LAST_W + AGE_W + THR_W + (MEAN_W if args.show_mean else 0) + 10)
        print(sep)
        base_hdr = f"{{:<{KEY_W}}} {{:>{N_W}}} {{:>{OK_W}}} {{:>{P50_W}}} {{:>{P95_W}}} {{:>{LAST_W}}} {{:>{AGE_W}}} {{:>{THR_W}}}"
        mean_hdr = base_hdr + f" {{:>{MEAN_W}}}"
        hdr = base_hdr.format("Series (Resolver[/Target][Route])", "N", "OK%", "p50", "p95", "Last", "Age", "Thr")
        if args.show_mean:
            hdr = mean_hdr.format("Series (Resolver[/Target][Route])", "N", "OK%", "p50", "p95", "Last", "Age", "Thr", "Mean")
        print(hdr)
        print(sep)

        rows = summarize()
        if not rows:
            print("(waiting for data…)")
        else:
            for r in rows:
                # Base strings with fixed widths FIRST (so colors don't affect alignment)
                key_str = r["key"] if isinstance(r["key"], str) else f"{r['key'][0]} / {r['key'][1]}"
                key_str = (key_str[:KEY_W]) if len(key_str) > KEY_W else key_str  # trim if too long

                n_str   = f"{r['count']:>{N_W}d}"
                ok_str  = fmt_pct_fixed(r["ok_rate"], OK_W)
                p50_str = fmt_ms_fixed(r["p50"], P50_W)
                p95_str = fmt_ms_fixed(r["p95"], P95_W)
                last_str= fmt_ms_fixed(r["last"], LAST_W)
                age_str = f"{int(r['age']):>{AGE_W}d}s"
                thr_str = ("*" if r["rule"] else "").rjust(THR_W)
                mean_str= fmt_ms_fixed(r["mean"], MEAN_W) if args.show_mean else None

                # Colorize AFTER formatting (colors wrap full-width strings)
                # OK%
                if r["ok_rate"] < r["ok_thr"]:
                    ok_str = red(ok_str)
                elif r["ok_rate"] < 99.9:
                    ok_str = yellow(ok_str)
                else:
                    ok_str = green(ok_str)
                # p95
                if r["p95"] is not None and not (isinstance(r["p95"], float) and math.isnan(r["p95"])) and r["p95"] > r["p95_thr"]:
                    p95_str = red(p95_str)
                # mean hint (compare to p95 threshold so it's a soft signal)
                if args.show_mean and r["mean"] is not None and not (isinstance(r["mean"], float) and math.isnan(r["mean"])) and r["mean"] > r["p95_thr"]:
                    mean_str = yellow(mean_str)

                # Print row
                base_row = f"{{:<{KEY_W}}} {{:>{N_W}}} {{:>{OK_W}}} {{:>{P50_W}}} {{:>{P95_W}}} {{:>{LAST_W}}} {{:>{AGE_W}}} {{:>{THR_W}}}"
                if args.show_mean:
                    base_row += f" {{:>{MEAN_W}}}"
                    print(base_row.format(key_str, n_str, ok_str, p50_str, p95_str, last_str, age_str, thr_str, mean_str))
                else:
                    print(base_row.format(key_str, n_str, ok_str, p50_str, p95_str, last_str, age_str, thr_str))

        print(sep)
        print("Legend: OK% < per-series threshold → RED | p95 > per-series threshold → RED | Thr=* has custom rule")
        print("Tip: --rule \"pattern=.*_ldap\\._tcp.*; ok=90; p95=15\"  |  --rules-file rules.json")
        time.sleep(args.refresh)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
