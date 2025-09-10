#!/usr/bin/env python3
# DNSHealthScatter.py — raw DNS latency scatter (no smoothing)
# Stdlib + matplotlib. Colors failures; marks TCP; group by resolver|route|target.
# Works headless (PNG only).

import argparse, csv, datetime as dt, os, math, random, re
from collections import defaultdict
import matplotlib
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

def load_rows_from_csv(csv_path):
    """Yield dicts with: ts, resolver, target, latency, ok, rcode, used_tcp, src_ip, dst_ip"""
    with open(csv_path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            return
        has_src = "src_ip" in r.fieldnames
        has_dst = "dst_ip" in r.fieldnames
        has_tcp = "used_tcp" in r.fieldnames
        for row in r:
            try:
                ts = parse_ts(row["timestamp_utc"])
                resolver = row["resolver"]
                target = f'{row["query"]}({row["type"]})'
                lat = float(row["latency_ms"])
                ok = (row["rcode"] == "NOERROR") and (row["success"] in ("1","True","true"))
                rcode = row["rcode"]
                used_tcp = (row.get("used_tcp","0") in ("1","True","true")) if has_tcp else False
                src_ip = row.get("src_ip","") if has_src else ""
                dst_ip = row.get("dst_ip","") if has_dst else resolver
                yield {"ts": ts, "resolver": resolver, "target": target, "lat": lat,
                       "ok": ok, "rcode": rcode, "used_tcp": used_tcp,
                       "src_ip": src_ip, "dst_ip": dst_ip}
            except Exception:
                continue

def discover_csv_path(csv_dir, date_str):
    return os.path.join(csv_dir, f"dns_trend_{date_str}.csv")

def main():
    ap = argparse.ArgumentParser(description="Raw DNS latency scatter (PNG)")
    # Input options
    ap.add_argument("--csv", help="Path to a specific CSV (overrides --csv-dir/--date)")
    ap.add_argument("--csv-dir", help="Folder with dns_trend_YYYY-MM-DD.csv")
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).strftime(DATEFMT),
                    help="UTC date (YYYY-MM-DD). Default: today")
    # Grouping / filtering
    ap.add_argument("--group-by", choices=["resolver","route","target"], default="resolver",
                    help="Facet rows by resolver (default), route (src→dst), or target")
    ap.add_argument("--resolver", action="append", help="Filter to resolver(s) (repeatable)")
    ap.add_argument("--route", action="append", help="Filter to route(s) like '10.0.0.5→167.190.40.21' (repeatable)")
    ap.add_argument("--target", action="append", help="Filter to exact target(s) like 'ddc01.corp.local(A)' (repeatable)")
    ap.add_argument("--match", help="Regex to filter targets (applied to 'name(type)')")
    # Visual options
    ap.add_argument("--y-max", type=float, default=None, help="Cap y-axis (ms), e.g. 300")
    ap.add_argument("--threshold-ms", type=float, default=None, help="Horizontal threshold line, e.g. 10")
    ap.add_argument("--jitter", type=float, default=0.0, help="Vertical jitter (ms) to separate overlaps, e.g. 0.3")
    ap.add_argument("--dot-size", type=float, default=12.0, help="Marker size")
    ap.add_argument("--max-facets", type=int, default=8, help="Cap number of facet rows (default 8)")
    ap.add_argument("--title", default="DNS Raw Latency (per query)", help="Figure title")
    # Output
    ap.add_argument("--out", required=True, help="Save PNG to this path")
    args = ap.parse_args()

    # Resolve CSV path
    if args.csv:
        csv_path = args.csv
    else:
        if not args.csv_dir:
            raise SystemExit("[ERROR] Provide --csv or --csv-dir (with optional --date).")
        csv_path = discover_csv_path(args.csv_dir, args.date)

    if not os.path.exists(csv_path):
        raise SystemExit(f"[ERROR] File not found: {csv_path}")

    # Headless backend for PNG
    if not os.environ.get("DISPLAY"):
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # import after backend set

    # Load rows
    rows = list(load_rows_from_csv(csv_path))
    if not rows:
        raise SystemExit("[INFO] No rows parsed from CSV.")

    # Filters
    if args.resolver:
        allowed = set(args.resolver)
        rows = [r for r in rows if r["resolver"] in allowed]
    if args.route:
        want = set(args.route)
        rows = [r for r in rows if f'{r.get("src_ip","")}→{r.get("dst_ip","") or r["resolver"]}' in want]
    if args.target:
        want_t = set(args.target)
        rows = [r for r in rows if r["target"] in want_t]
    if args.match:
        rx = re.compile(args.match)
        rows = [r for r in rows if rx.search(r["target"])]

    if not rows:
        raise SystemExit("[INFO] No rows after filters.")

    # Grouping
    def series_key(r):
        if args.group_by == "route":
            return f'{r.get("src_ip","")}→{r.get("dst_ip","") or r["resolver"]}'
        elif args.group_by == "target":
            return r["target"]
        else:
            return r["resolver"]

    groups = defaultdict(list)
    for r in rows:
        groups[series_key(r)].append(r)

    # Cap number of facets
    keys = sorted(groups.keys(), key=str)
    if len(keys) > args.max_facets:
        # rank by failures first, then count
        scored = []
        for k in keys:
            g = groups[k]
            cnt = len(g)
            has_fail = any(not x["ok"] for x in g)
            scored.append((k, has_fail, cnt))
        scored.sort(key=lambda t: (t[1], t[2]), reverse=True)
        keys = [k for k, _, _ in scored[:args.max_facets]]

    height = 2.5 * max(1, len(keys)) + 1.2
    fig, axes = plt.subplots(len(keys), 1, figsize=(14, height), sharex=True)

    # --- FIX: always flatten to a list of Axes objects ---
    if isinstance(axes, (list, tuple)):
        axes = list(axes)
    elif hasattr(axes, "flatten"):
        axes = axes.flatten().tolist()
    else:
        axes = [axes]

    # Colors
    COL_OK = "#1565C0"   # blue circle
    COL_FAIL = "#C62828" # red x
    COL_TCP = "#6A1B9A"  # purple square

    # Draw each facet
    for ax, key in zip(axes, keys):
        g = groups[key]
        ok_x, ok_y = [], []
        ko_x, ko_y = [], []
        tcp_x, tcp_y = [], []

        for r in g:
            x = mdates.date2num(r["ts"])
            y = r["lat"] + (random.uniform(-args.jitter, args.jitter) if args.jitter > 0 else 0.0)
            if r["ok"]:
                ok_x.append(x); ok_y.append(y)
            else:
                ko_x.append(x); ko_y.append(y)
            if r["used_tcp"]:
                tcp_x.append(x); tcp_y.append(y)

        if ko_x:
            ax.scatter(ko_x, ko_y, s=args.dot_size, alpha=0.9, marker="x", label="Fail", color=COL_FAIL)
        if ok_x:
            ax.scatter(ok_x, ok_y, s=args.dot_size, alpha=0.6, marker="o", label="OK", color=COL_OK)
        if tcp_x:
            ax.scatter(tcp_x, tcp_y, s=args.dot_size*0.9, alpha=0.6, marker="s", label="TCP", color=COL_TCP)

        if args.threshold_ms is not None:
            ax.axhline(args.threshold_ms, linestyle="--", linewidth=1.0, color="#555555")

        if args.y_max:
            ax.set_ylim(0, args.y_max)

        # stats for title
        cnt = len(g)
        fails = sum(1 for r in g if not r["ok"])
        okpct = 100.0 * (cnt - fails) / cnt if cnt else 0.0
        ax.set_title(f"{args.group_by}: {key}   |   N={cnt}, OK={okpct:.1f}%, Fails={fails}", fontsize=10)
        ax.set_ylabel("ms")
        ax.grid(True, axis="y", alpha=0.18)

    # X axis formatting
    axes[-1].set_xlabel("Time (UTC)")
    for ax in axes:
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    fig.suptitle(args.title, fontsize=14, fontweight="bold", y=0.995)
    fig.tight_layout(rect=[0, 0, 1, 0.97])

    # Build a single shared legend from unique labels
    seen_labels = set()
    handles, labels = [], []
    for ax in axes:
        h, l = ax.get_legend_handles_labels()
        for hi, li in zip(h, l):
            if li not in seen_labels:
                seen_labels.add(li)
                handles.append(hi)
                labels.append(li)
    if handles:
        fig.legend(handles, labels, loc="upper right")

    plt.savefig(args.out, dpi=140)
    print(f"[OK] Saved PNG -> {args.out}")

if __name__ == "__main__":
    main()
