#!/usr/bin/env python3
# DNSHealthGraph_raw.py — plot raw DNS queries (no smoothing)
# Stdlib + matplotlib only. Colors failures; optional per-target split. Headless-safe PNG output.

import argparse, csv, datetime as dt, os, math, random
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

def load_rows(csv_path, include_all):
    """
    Yield dicts with: ts, resolver, target, latency, ok, rcode, used_tcp
    """
    with open(csv_path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                ts = parse_ts(row["timestamp_utc"])
                resolver = row["resolver"]
                target = f'{row["query"]}({row["type"]})'
                lat = float(row["latency_ms"])
                ok = (row["rcode"] == "NOERROR") and (row["success"] in ("1","True","true"))
                if not include_all and not ok:
                    # keep failures too if include_all is False? We *do* want failures.
                    pass
                yield {
                    "ts": ts,
                    "resolver": resolver,
                    "target": target,
                    "lat": lat,
                    "ok": ok,
                    "rcode": row["rcode"],
                    "used_tcp": row.get("used_tcp","0") in ("1","True","true")
                }
            except Exception:
                continue

def main():
    ap = argparse.ArgumentParser(description="Raw DNS latency scatter from collector CSV")
    ap.add_argument("--csv-dir", required=True, help="Folder with dns_trend_YYYY-MM-DD.csv")
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).strftime(DATEFMT),
                    help="UTC date (YYYY-MM-DD). Default: today")
    ap.add_argument("--resolver", action="append",
                    help="Filter to one or more resolvers (repeatable). Default: all")
    ap.add_argument("--target", action="append",
                    help="Filter to one or more targets (repeatable, format name(type)). Default: all")
    ap.add_argument("--group-by-target", action="store_true",
                    help="Facet per target (rows) instead of per resolver")
    ap.add_argument("--y-max", type=float, default=None,
                    help="Cap Y axis (ms). Useful to clip huge spikes (e.g., 500)")
    ap.add_argument("--threshold-ms", type=float, default=None,
                    help="Optional horizontal threshold line (e.g., 10)")
    ap.add_argument("--jitter", type=float, default=0.0,
                    help="Apply small vertical jitter (ms) to separate overlapping points (e.g., 0.3)")
    ap.add_argument("--dot-size", type=float, default=12.0,
                    help="Marker size for points")
    ap.add_argument("--out", type=str, required=True,
                    help="Save PNG to this path (headless-safe)")
    ap.add_argument("--include-all", action="store_true",
                    help="Include all rows even if parsing oddities occur; default already includes failures")
    args = ap.parse_args()

    # Headless backend for PNG
    if not os.environ.get("DISPLAY"):
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # import after backend set

    csv_path = os.path.join(args.csv_dir, f"dns_trend_{args.date}.csv")
    if not os.path.exists(csv_path):
        raise SystemExit(f"[ERROR] File not found: {csv_path}")

    # Load & filter
    rows = list(load_rows(csv_path, include_all=args.include_all))
    if args.resolver:
        rows = [r for r in rows if r["resolver"] in args.resolver]
    if args.target:
        wanted = set(args.target)
        rows = [r for r in rows if r["target"] in wanted]

    if not rows:
        raise SystemExit("[INFO] No matching rows after filters.")

    # Grouping: per resolver (default) or per target
    groups = defaultdict(list)
    if args.group_by_target:
        for r in rows:
            groups[r["target"]].append(r)
        facet_label = "Target"
    else:
        for r in rows:
            groups[r["resolver"]].append(r)
        facet_label = "Resolver"

    # Sort keys for consistent ordering
    keys = sorted(groups.keys(), key=str)

    # Layout: one subplot per group (cap to avoid comically tall figure)
    n = len(keys)
    max_rows = min(n, 8)  # render up to 8 facets; if more, we paginate by time range instead (not implemented here)
    if n > 8:
        keys = keys[:8]

    height = 2.4 * max_rows + 1.2
    fig, axes = plt.subplots(max_rows, 1, figsize=(14, height), sharex=True)
    if max_rows == 1:
        axes = [axes]

    # Prepare scatter data for each facet
    for ax, key in zip(axes, keys):
        g = groups[key]
        # split successes vs failures; also mark TCP-used
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

        # plot failures first so successes overlay cleanly
        if ko_x:
            ax.scatter(ko_x, ko_y, s=args.dot_size, alpha=0.9, marker="x", label="Fail", color="#C62828")
        if ok_x:
            ax.scatter(ok_x, ok_y, s=args.dot_size, alpha=0.6, marker="o", label="OK", color="#1565C0")
        if tcp_x:
            ax.scatter(tcp_x, tcp_y, s=args.dot_size*0.9, alpha=0.6, marker="s", label="TCP", color="#6A1B9A")

        # threshold line
        if args.threshold_ms is not None:
            ax.axhline(args.threshold_ms, linestyle="--", linewidth=1.0, color="#555555")

        # y cap
        if args.y_max:
            ax.set_ylim(0, args.y_max)

        # title + small stats
        cnt = len(g)
        fails = sum(1 for r in g if not r["ok"])
        okpct = 100.0 * (cnt - fails) / cnt if cnt else 0.0
        ax.set_title(f"{facet_label}: {key}   |   N={cnt}, OK={okpct:.1f}%, Fails={fails}", fontsize=10)

        ax.set_ylabel("ms")

    # X axis formatting
    axes[-1].set_xlabel("Time (UTC)")
    for ax in axes:
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        ax.grid(True, axis="y", alpha=0.2)

    # Global legend (combine unique labels)
    handles, labels = [], []
    for ax in axes:
        h, l = ax.get_legend_handles_labels()
        for hi, li in zip(h, l):
            if li not in labels:
                labels.append(li); handles.append(hi)
    if handles:
        fig.legend(handles, labels, loc="upper right")

    plt.tight_layout()
    plt.savefig(args.out, dpi=140)
    print(f"[OK] Saved PNG -> {args.out}")

if __name__ == "__main__":
    main()
