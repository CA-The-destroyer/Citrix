#!/usr/bin/env python3
# DNSHealthGraph.py — rolling p50 / p95 plots from DNSHealthChk CSV (robust)
# Stdlib + matplotlib only.

import argparse, csv, datetime as dt, os, math
from collections import defaultdict, deque
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

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
    ap.add_argument("--window", type=int, default=60, help="Rolling window size in samples (default 60)")
    ap.add_argument("--group-by-target", action="store_true",
                    help="Plot resolver+target lines instead of resolver-only")
    ap.add_argument("--only-ok", action="store_true", default=True,
                    help="Only include NOERROR rows (default True). Use --no-only-ok to include all.")
    ap.add_argument("--no-only-ok", dest="only_ok", action="store_false")
    ap.add_argument("--include-raw", action="store_true", help="Overlay faint raw latency dots")
    ap.add_argument("--threshold-ms", type=float, default=None, help="Optional horizontal threshold line (e.g., 10)")
    args = ap.parse_args()

    csv_path = os.path.join(args.csv_dir, f"dns_trend_{args.date}.csv")
    if not os.path.exists(csv_path):
        raise SystemExit(f"[ERROR] File not found: {csv_path}")

    # Data structures per series
    roll = defaultdict(lambda: deque(maxlen=args.window))
    times = defaultdict(list)
    p50s  = defaultdict(list)
    p95s  = defaultdict(list)
    raws_t = defaultdict(list)
    raws_y = defaultdict(list)

    # Freeze flags to avoid inner-scope surprises
    group_by_target = args.group_by_target
    only_ok = args.only_ok
    include_raw = args.include_raw

    def key_for(resolver, target):
        return (resolver, target) if group_by_target else resolver

    # Ingest rows
    for ts, resolver, target, lat, ok in load_rows(csv_path):
        if only_ok and not ok:
            continue
        k = key_for(resolver, target)

        if include_raw:
            raws_t[k].append(ts)
            raws_y[k].append(lat)

        roll[k].append(lat)
        times[k].append(ts)
        sv = sorted(roll[k])
        p50 = percentile(sv, 50)
        p95 = percentile(sv, 95)
        # Guard: ensure p95 >= p50; if NaN, fallback
        if math.isnan(p50) and not math.isnan(p95):
            p50 = p95
        if math.isnan(p95) and not math.isnan(p50):
            p95 = p50
        if not math.isnan(p50) and not math.isnan(p95) and p95 < p50:
            p95 = p50

        p50s[k].append(p50)
        p95s[k].append(p95)

    if not times:
        raise SystemExit("[INFO] No data to plot (check date/path or window too large).")

    # Plot
    fig, ax = plt.subplots(figsize=(12, 7))

    for k in sorted(times.keys(), key=lambda x: str(x)):
        ts_list = times[k]
        p50_list = p50s[k]
        p95_list = p95s[k]

        # Convert to Matplotlib date numbers (robust for tz-aware datetimes)
        x = [mdates.date2num(t) for t in ts_list]

        label = k if isinstance(k, str) else f"{k[0]} / {k[1]}"
        ax.plot(x, p50_list, linewidth=1.8, label=f"{label} p50")

        # Shaded band p50 → p95 (handle NaNs by collapsing band)
        upper = []
        lower = []
        for a, b in zip(p50_list, p95_list):
            if math.isnan(a) and math.isnan(b):
                upper.append(math.nan); lower.append(math.nan)
            elif math.isnan(a):
                upper.append(b); lower.append(b)
            elif math.isnan(b):
                upper.append(a); lower.append(a)
            else:
                lo = min(a, b); hi = max(a, b)
                lower.append(lo); upper.append(hi)

        ax.fill_between(x, lower, upper, alpha=0.18)

        if include_raw and raws_t.get(k):
            xr = [mdates.date2num(t) for t in raws_t[k]]
            ax.scatter(xr, raws_y[k], s=8, alpha=0.25)

    # Optional threshold line
    if args.threshold_ms is not None:
        ax.axhline(args.threshold_ms, linestyle="--", linewidth=1.2)

    ax.set_title(f"DNS Rolling Latency (window={args.window} samples) — p50 line, p50→p95 band")
    ax.set_xlabel("Time (UTC)")
    ax.set_ylabel("Latency (ms)")
    ax.legend(fontsize="small", ncol=2)

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    fig.autofmt_xdate()
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
