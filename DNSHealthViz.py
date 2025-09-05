#!/usr/bin/env python3
# DNSHealthViz_console.py — live console dashboard for DNSHealthChk CSVs
# Stdlib only: tails today's CSV and prints a rolling table.

import argparse, csv, datetime as dt, os, time, collections, math

DATEFMT = "%Y-%m-%d"

def latest_csv(csv_dir: str) -> str:
    return os.path.join(csv_dir, f"dns_trend_{dt.datetime.utcnow().strftime(DATEFMT)}.csv")

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

def parse_row(line: str):
    # Columns:
    # timestamp_utc,resolver,query,type,success,latency_ms,rcode,answers,ttl,used_tcp,error
    r = next(csv.reader([line]))
    # pad to 11
    while len(r) < 11:
        r.append("")
    ts_iso, resolver, qname, rtype, success, latency_ms, rcode, answers, ttl, used_tcp, err = r[:11]
    try:
        ts = dt.datetime.fromisoformat(ts_iso.replace("Z","+00:00"))
    except Exception:
        ts = dt.datetime.utcnow()
    try:
        lat = float(latency_ms)
    except Exception:
        lat = math.nan
    ok = (rcode == "NOERROR") and (success in ("1", "True", "true"))
    return ts, resolver, qname, rtype, ok, lat, rcode

def clear_console():
    # Windows cls / ANSI fallback
    if os.name == "nt":
        os.system("cls")
    else:
        print("\033[2J\033[H", end="")

def fmt_ms(x):
    if x is None or math.isnan(x):
        return "—"
    if x >= 1000:
        return f"{x/1000:.2f}s"
    return f"{x:.0f}ms"

def percentile(arr, p):
    if not arr:
        return None
    a = sorted(arr)
    k = max(0, min(len(a)-1, int(round((p/100.0)*(len(a)-1)))))
    return a[k]

def main():
    ap = argparse.ArgumentParser(description="Console dashboard for DNSHealthChk CSVs (no GUI)")
    ap.add_argument("--csv-dir", required=True, help="Directory where DNSHealthChk writes CSVs (e.g., C:\\temp\\dns_trend)")
    ap.add_argument("--window", type=int, default=300, help="Rolling points per series (default 300)")
    ap.add_argument("--group-by-target", action="store_true",
                    help="If set, show lines per resolver+target; otherwise aggregate per resolver.")
    ap.add_argument("--refresh", type=float, default=2.0, help="Seconds between screen refresh (default 2s)")
    args = ap.parse_args()

    current_day = dt.datetime.utcnow().strftime(DATEFMT)
    csv_path = latest_csv(args.csv_dir)
    file_pos = 0

    # series buffers: key -> deque of (ts, ok(0/1), latency_ms)
    series = collections.defaultdict(lambda: collections.deque(maxlen=args.window))

    # last-seen timestamp per key for staleness display
    last_ts = {}

    def key_of(resolver, qname, rtype):
        return (resolver, f"{qname} ({rtype})") if args.group_by_target else resolver

    def roll_if_new_day():
        nonlocal current_day, csv_path, file_pos
        today = dt.datetime.utcnow().strftime(DATEFMT)
        if today != current_day:
            current_day = today
            csv_path = latest_csv(args.csv_dir)
            file_pos = 0

    def ingest(lines):
        for line in lines:
            ts, resolver, qname, rtype, ok, lat, rcode = parse_row(line)
            k = key_of(resolver, qname, rtype)
            series[k].append((ts, 1 if ok else 0, lat))
            last_ts[k] = ts

    def summarize():
        rows = []
        now = dt.datetime.utcnow()
        for k, dq in series.items():
            if not dq:
                continue
            oks = [v[1] for v in dq]
            lats = [v[2] for v in dq if not math.isnan(v[2])]
            # stats
            cnt = len(dq)
            ok_rate = (sum(oks)/cnt)*100.0
            p50 = percentile(lats, 50) if lats else None
            p95 = percentile(lats, 95) if lats else None
            last_latency = next((v[2] for v in reversed(dq) if not math.isnan(v[2])), math.nan)
            age_s = (now - last_ts.get(k, now)).total_seconds()
            rows.append({
                "key": k,
                "count": cnt,
                "ok_rate": ok_rate,
                "p50": p50,
                "p95": p95,
                "last": last_latency,
                "age": age_s
            })
        # sort: worst ok_rate first, then highest p95
        rows.sort(key=lambda r: (r["ok_rate"], -(r["p95"] if r["p95"] is not None else -1)), reverse=False)
        return rows

    while True:
        roll_if_new_day()
        file_pos, lines = tail_csv(csv_path, file_pos)
        if lines:
            ingest(lines)

        # render
        rows = summarize()
        clear_console()
        print("DNSHealthViz (console)   |   Source:", csv_path)
        print("Window size:", args.window, "points    Refresh:", args.refresh, "s    Time (UTC):", dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        print("-"*110)
        hdr = "{:<34} {:>5} {:>9} {:>10} {:>10} {:>9} {:>7}".format(
            "Series (Resolver[/Target])", "N", "OK%", "p50", "p95", "Last", "Age"
        )
        print(hdr)
        print("-"*110)
        if not rows:
            print("(waiting for data…)")
        else:
            for r in rows:
                key_str = r["key"] if isinstance(r["key"], str) else f"{r['key'][0]} / {r['key'][1]}"
                # formatting and simple status color (ANSI) if available
                okpct = f"{r['ok_rate']:.1f}"
                p50 = fmt_ms(r["p50"])
                p95 = fmt_ms(r["p95"])
                last = fmt_ms(r["last"])
                age = f"{int(r['age']):>3}s"
                line = "{:<34} {:>5} {:>9} {:>10} {:>10} {:>9} {:>7}".format(
                    key_str[:34], r["count"], okpct, p50, p95, last, age
                )
                print(line)

        print("-"*110)
        print("Legend: OK% = success rate in window | p50/p95 = latency percentiles | Last = most recent latency | Age = secs since last sample")
        time.sleep(args.refresh)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
