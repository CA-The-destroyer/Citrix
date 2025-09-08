#!/usr/bin/env python3
# DNSHealthGraph.py — rolling p50 / p95 plots from DNSHealthChk CSV (matplotlib + stdlib)

import argparse, csv, datetime as dt, os, math
from collections import defaultdict, deque
import matplotlib.pyplot as plt

DATEFMT = "%Y-%m-%d"

def parse_ts(s: str) -> dt.datetime:
    try:
        ts = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        ts = dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts

def percentile(sorted_vals, p):
    if not sorted_vals:
        return math.nan
    n = len(sorted_vals)
    if n == 1:
        return float(sorted_vals[0])
    # nearest-rank on [0, n-1]
    idx = max(0, min(n - 1, int(round((p / 100.0) * (n - 1)))))
    return float(sorted_vals[idx])

def load_rows(csv_path):
    """Yield (ts, resolver, target_str, latency_ms, ok) in file order."""
    with open(csv_path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                ts = parse_ts(row["timestamp_utc"])
                resolver = row["resolver"]
                target = f'{row["query"]}({row["type"]})'
                lat = float(row["latency_ms"])
                ok = (row["rcode"] == "NOERROR") and (row["success"] in ("1", "True", "true"))
                yield ts, resolver, target, lat, ok
            except Exception:
                continue

def main():
    ap = argparse.ArgumentParser(description="Plot rolling p50/p95 DNS latency from collector CSV")
    ap.add_argument("--csv-dir", required=True, help="Folder with dns_trend_YYYY-MM-DD.csv")
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).strftime(DATEFMT),
                    help="UTC date (YYYY-MM-DD). Default: today")
    ap.add_argument("--window", type=int, default=60,
                    help="Rolling window size in samples (default 60)")
    ap.add_argument("--group-by-target", action="store_true",
                    help="Plot resolver+target lines instead of resolver-only")
    ap.add_argument("--only-ok", action="store_true",
                    help="Ignore non-NOERROR rows when computing percentiles (default on).")
    ap.add_argument("--include-raw", action="store_true",
                    help="Overlay faint raw latency dots")
    args = ap.parse_args()

    csv_path = os.path.join(args.csv_dir, f"dns_trend_{args.date}.csv")
    if not os.path.exists(csv_path):
        raise SystemExit(f"[ERROR] File not found: {csv_path}")

    # data structures: per series key store time, rolling q, and outputs
    # key = resolver or (resolver,target)
    roll = defaultdict(lambda: deque(maxlen=args.window))
    times = defaultdict(list)
    p50s  = defaultdict(list)
    p95s  = defaultdict(list)
    raws_t = defaultdict(list)
    raws_y = defaultdict(list)

    def key_for(resolver, target):
        return (resolver, target) if args.group_by_target else resolver

    # ingest
    for ts, resolver, target, lat, ok in load_rows(csv_path):
        if args.only_ok and not ok:
            continue
        k = key_for(resolver, target)
        # append raw
        if args.include-raw:
            raws_t[k].append(ts); raws_y[k].append(lat)
        # update rolling window + compute percentiles
        roll[k].append(lat)
        times[k].append(ts)
        # compute percentiles on a sorted copy (window is small)
        sorted_vals = sorted(roll[k])
        p50s[k].append(percentile(sorted_vals, 50))
        p95s[k].append(percentile(sorted_vals, 95))

    if not times:
        raise SystemExit("[INFO] No data to plot (check date/path or window too large).")

    # plot
    plt.figure(figsize=(12, 7))
    ax = plt.gca()

    for k in sorted(times.keys(), key=lambda x: str(x)):
        ts_list = times[k]
        p50_list = p50s[k]
        p95_list = p95s[k]

        # p50 line
        label = k if isinstance(k, str) else f"{k[0]} / {k[1]}"
        line, = ax.plot(ts_list, p50_list, linewidth=1.8, label=f"{label} p50")

        # shaded band p50->p95
        ax.fill_between(ts_list, p50_list, p95_list, alpha=0.18)

        # raw points (optional)
        if args.include-raw and raws_t.get(k):
            ax.scatter(raws_t[k], raws_y[k], s=8, alpha=0.25)

    ax.set_title(f"DNS Rolling Latency (window={args.window} samples) — p50 line, p50→p95 band")
    ax.set_xlabel("Time (UTC)")
    ax.set_ylabel("Latency (ms)")
    ax.legend(fontsize="small", ncol=2)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
