#!/usr/bin/env python3
# DNSHealthExecReport.py — Executive-friendly DNS health report (PNG)
# Adds --trend-by {overall,resolver,route} for per-minute p95 trend lines.
# Route-aware offenders (target + src->dst). Deps: matplotlib (no pandas/numpy).

import argparse, csv, datetime as dt, os, math, collections
import matplotlib
import matplotlib.dates as mdates

DATEFMT = "%Y-%m-%d"

# Thresholds — tune for your LAN
THRESH_OK = 95.0   # %
THRESH_P95 = 10.0  # ms

def parse_ts(s: str) -> dt.datetime:
    try:
        ts = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        ts = dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts

def percentile(sorted_vals, p):
    if not sorted_vals: return math.nan
    n = len(sorted_vals)
    if n == 1: return float(sorted_vals[0])
    idx = max(0, min(n-1, int(round((p/100.0)*(n-1)))))
    return float(sorted_vals[idx])

def load_rows(csv_path):
    """Yield dict rows for this report; handles optional src_ip/dst_ip."""
    with open(csv_path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        has_src = "src_ip" in (r.fieldnames or [])
        has_dst = "dst_ip" in (r.fieldnames or [])
        for row in r:
            try:
                ts = parse_ts(row["timestamp_utc"])
                resolver = row["resolver"]
                target = f'{row["query"]}({row["type"]})'
                lat = float(row["latency_ms"])
                ok = (row["rcode"] == "NOERROR") and (row["success"] in ("1","True","true"))
                src_ip = row.get("src_ip", "") if has_src else ""
                dst_ip = row.get("dst_ip", "") if has_dst else resolver
                yield {"ts": ts, "resolver": resolver, "target": target,
                       "lat": lat, "ok": ok, "src_ip": src_ip, "dst_ip": dst_ip}
            except Exception:
                continue

def bucket_minute(ts: dt.datetime) -> dt.datetime:
    return ts.replace(second=0, microsecond=0)

def fmt_ms(x):
    if x is None or math.isnan(x): return "—"
    return f"{x:.1f} ms" if x < 1000 else f"{x/1000:.2f} s"

def main():
    ap = argparse.ArgumentParser(description="Executive PNG for DNS Health (p95 trend + route-aware offenders)")
    ap.add_argument("--csv-dir", required=True, help="Folder with dns_trend_YYYY-MM-DD.csv")
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).strftime(DATEFMT),
                    help="UTC date (YYYY-MM-DD). Default: today")
    ap.add_argument("--minutes", type=int, default=60, help="Lookback window in minutes (default 60)")
    ap.add_argument("--resolver", action="append",
                    help="Filter to one or more resolvers (repeatable). Default: all")
    ap.add_argument("--out", required=True, help="PNG output path (headless-safe)")
    ap.add_argument("--topn", type=int, default=8, help="Top-N offending (target+route) groups (default 8)")
    ap.add_argument("--ok-thresh", type=float, default=THRESH_OK, help="OK%% threshold")
    ap.add_argument("--p95-thresh", type=float, default=THRESH_P95, help="p95 threshold in ms")
    ap.add_argument("--trend-by", choices=["overall","resolver","route"], default="overall",
                    help="Group p95 trend line by: overall (one line), resolver, or route (src→dst)")
    ap.add_argument("--trend-max-series", type=int, default=8,
                    help="When trend-by != overall, cap number of series to avoid clutter (default 8)")
    args = ap.parse_args()

    # Headless-safe backend when saving
    if not os.environ.get("DISPLAY"):
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # import after backend selection

    csv_path = os.path.join(args.csv_dir, f"dns_trend_{args.date}.csv")
    if not os.path.exists(csv_path):
        raise SystemExit(f"[ERROR] Not found: {csv_path}")

    rows = list(load_rows(csv_path))
    if args.resolver:
        allowed = set(args.resolver)
        rows = [r for r in rows if r["resolver"] in allowed]
    if not rows:
        raise SystemExit("[INFO] No matching data in file.")

    # Time filter
    now = dt.datetime.now(dt.timezone.utc)
    start_ts = now - dt.timedelta(minutes=args.minutes)
    rows = [r for r in rows if r["ts"] >= start_ts]
    if not rows:
        raise SystemExit("[INFO] No samples in the last window; increase --minutes or check date.")

    # ---------- KPIs over window ----------
    total = len(rows)
    ok_count = sum(1 for r in rows if r["ok"])
    ok_pct = (ok_count / total) * 100.0
    lats_all = sorted([r["lat"] for r in rows if r["ok"] and not math.isnan(r["lat"])])
    p50 = percentile(lats_all, 50)
    p95 = percentile(lats_all, 95)
    fail_count = total - ok_count

    # ---------- Trend: per-minute p95 ----------
    # Group key depending on trend-by
    def trend_key(r):
        if args.trend_by == "overall":
            return "overall"
        elif args.trend_by == "resolver":
            return r["resolver"]
        else:  # route
            return f"{r.get('src_ip','')}→{r.get('dst_ip','') or r['resolver']}"

    minute_bins_by_group = collections.defaultdict(lambda: collections.defaultdict(list))
    for r in rows:
        if r["ok"] and not math.isnan(r["lat"]):
            g = trend_key(r)
            minute_bins_by_group[g][bucket_minute(r["ts"])].append(r["lat"])

    # Build trend series (group -> (x[], y[]))
    trend_series = {}
    for g, bins in minute_bins_by_group.items():
        xs, ys = [], []
        for t in sorted(bins.keys()):
            sv = sorted(bins[t])
            xs.append(mdates.date2num(t))
            ys.append(percentile(sv, 95))
        if xs:
            trend_series[g] = (xs, ys)

    # If too many groups, pick the "worst" N by recent p95
    if args.trend_by != "overall" and len(trend_series) > args.trend_max_series:
        ranked = []
        for g, (xs, ys) in trend_series.items():
            last = ys[-1] if ys else float("nan")
            ranked.append((g, last if not math.isnan(last) else -1.0))
        # sort by last p95 desc (NaNs last)
        ranked.sort(key=lambda t: (t[1] if t[1] is not None else -1.0), reverse=True)
        keep = set(g for g, _ in ranked[:args.trend_max_series])
        trend_series = {g: v for g, v in trend_series.items() if g in keep}

    # ---------- Route-aware offenders: (target, src, dst) ----------
    per_group_lats = collections.defaultdict(list)         # (target, src, dst) -> [lat...]
    per_group_ok   = collections.defaultdict(lambda: [0,0])# (target, src, dst) -> [ok, total]
    for r in rows:
        key = (r["target"], r.get("src_ip",""), r.get("dst_ip","") or r["resolver"])
        per_group_ok[key][1] += 1
        if r["ok"]:
            per_group_ok[key][0] += 1
            if not math.isnan(r["lat"]):
                per_group_lats[key].append(r["lat"])
    offenders = []
    for key, l in per_group_lats.items():
        target, src, dst = key
        sv = sorted(l)
        g_p95 = percentile(sv, 95)
        oks, tot = per_group_ok[key]
        opct = (oks/tot)*100.0 if tot else 0.0
        offenders.append((target, src, dst, g_p95, opct, tot))
    for key, (oks, tot) in per_group_ok.items():
        if key not in per_group_lats:  # all failed
            target, src, dst = key
            opct = (oks/tot)*100.0 if tot else 0.0
            offenders.append((target, src, dst, math.nan, opct, tot))
    offenders.sort(key=lambda x: (x[4], -(x[3] if not math.isnan(x[3]) else -1)))
    offenders = offenders[:args.topn]

    # ---------- Figure ----------
    fig = plt.figure(figsize=(14, 8))
    gs = fig.add_gridspec(3, 2, height_ratios=[1.2, 1.6, 1.8], width_ratios=[1,1], hspace=0.50, wspace=0.28)

    # Suptitle (kept high to avoid overlap)
    fig.suptitle("DNS Executive Assessment (route-aware)", fontsize=16, fontweight="bold", y=0.995)

    # KPI panel (top-left)
    ax_kpi = fig.add_subplot(gs[0, 0]); ax_kpi.axis("off")
    ax_kpi.text(0.0, 0.90, "DNS Health — Executive Summary", fontsize=14, fontweight="bold", va="top")
    ax_kpi.text(0.0, 0.76, f"Window: last {args.minutes} min   |   Dataset: {args.date} UTC   |   Trend by: {args.trend_by}",
                fontsize=10)

    kpi_y = 0.60; line_h = 0.13
    def ok_style(v):
        if v >= args.ok_thresh: return "good"
        if v >= max(90.0, args.ok_thresh - 5.0): return "warn"
        return "bad"
    def p95_style(v):
        if math.isnan(v): return "warn"
        if v <= args.p95_thresh: return "good"
        if v <= args.p95_thresh * 2: return "warn"
        return "bad"

    # Totals/OK/Fail
    ax_kpi.text(0.00, kpi_y,       "Total queries:", fontsize=12)
    ax_kpi.text(0.35, kpi_y,       f"{total:,}", fontsize=12)
    ax_kpi.text(0.60, kpi_y,       "OK%:", fontsize=12)
    ok_val = ok_style(ok_pct)
    ax_kpi.text(0.75, kpi_y,       f"{ok_pct:.1f}%",
                fontsize=12, color=("#2e7d32" if ok_val=="good" else "#ef6c00" if ok_val=="warn" else "#c62828"))
    ax_kpi.text(0.00, kpi_y - line_h, "Failures:", fontsize=12)
    ax_kpi.text(0.35, kpi_y - line_h, f"{fail_count:,}", fontsize=12, color=("#c62828" if fail_count>0 else "#2e7d32"))

    # p50/p95
    def fmt_ms2(x):
        if x is None or math.isnan(x): return "—"
        return f"{x:.1f} ms" if x < 1000 else f"{x/1000:.2f} s"
    p95_val = p95_style(p95); p50_val = p95_style(p50)
    ax_kpi.text(0.60, kpi_y - line_h,   "p50:", fontsize=12)
    ax_kpi.text(0.75, kpi_y - line_h,   fmt_ms2(p50),
                fontsize=12, color=("#2e7d32" if p50_val=="good" else "#ef6c00" if p50_val=="warn" else "#c62828"))
    ax_kpi.text(0.60, kpi_y - 2*line_h, "p95:", fontsize=12)
    ax_kpi.text(0.75, kpi_y - 2*line_h, fmt_ms2(p95),
                fontsize=12, color=("#2e7d32" if p95_val=="good" else "#ef6c00" if p95_val=="warn" else "#c62828"))

    # Threshold box (top-right)
    ax_th = fig.add_subplot(gs[0, 1]); ax_th.axis("off")
    ax_th.text(0.0, 0.95, "Thresholds", fontsize=12, fontweight="bold", va="top")
    ax_th.text(0.0, 0.75, f"OK% ≥ {args.ok_thresh:.1f}%  (green)\n"
                          f"p95 ≤ {args.p95_thresh:.1f} ms (green)\n"
                          f"Between = yellow; worse = red", fontsize=10, va="top")

    # Trend (middle row spans both cols)
    ax_tr = fig.add_subplot(gs[1, :])
    if trend_series:
        # If overall: single line named 'p95 (per-minute)'; else, one per group with legend
        if args.trend_by == "overall":
            xs, ys = next(iter(trend_series.values()))
            ax_tr.plot(xs, ys, linewidth=1.8, label="p95 (per-minute)")
        else:
            # Stable order: sort by series name
            for name in sorted(trend_series.keys()):
                xs, ys = trend_series[name]
                ax_tr.plot(xs, ys, linewidth=1.6, label=name)
        ax_tr.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        if args.p95_thresh:
            ax_tr.axhline(args.p95_thresh, linestyle="--", linewidth=1.2, color="#555555",
                          label=f"p95 threshold ({args.p95_thresh:.1f} ms)")
        title_suffix = "" if args.trend_by == "overall" else f" — {args.trend_by}"
        ax_tr.set_title(f"p95 Trend (per minute){title_suffix}", fontsize=12)
        ax_tr.set_ylabel("Latency (ms)")
        ax_tr.grid(True, axis="y", alpha=0.25)
        if args.trend_by != "overall" or True:
            ax_tr.legend(loc="upper right", fontsize=9, ncol=1)
    else:
        ax_tr.axis("off")
        ax_tr.text(0.5, 0.5, "Not enough OK samples for per-minute p95 trend",
                   ha="center", va="center", fontsize=11)

    # Offenders (bottom spans both cols) — route-aware
    ax_off = fig.add_subplot(gs[2, :])
    if offenders:
        labels, vals, colors, ann = [], [], [], []
        for (t, src, dst, p95_t, okpct_t, tot_t) in offenders:
            route = f"{src}→{dst}" if src or dst else "route n/a"
            label_text = f"{t}  [{route}]"
            labels.append(label_text)
            v = 0.0 if math.isnan(p95_t) else p95_t
            vals.append(v)
            # color by thresholds
            col = "#2e7d32"
            if math.isnan(p95_t) or p95_t > args.p95_thresh or okpct_t < args.ok_thresh:
                if okpct_t < args.ok_thresh or math.isnan(p95_t):
                    col = "#c62828"
                else:
                    col = "#ef6c00"
            colors.append(col)
            ann.append(f"{okpct_t:.1f}%")
        x = range(len(labels))
        bars = ax_off.bar(x, vals, color=colors)
        ax_off.set_ylabel("p95 (ms)")
        ax_off.set_title(f"Worst Targets by p95 (Top {len(labels)}) — labels show OK% (route-aware)", fontsize=12)
        def trim(s): return s if len(s) <= 48 else s[:45] + "…"
        ax_off.set_xticks(x)
        ax_off.set_xticklabels([trim(s) for s in labels], rotation=12, ha="right")
        for rect, txt in zip(bars, ann):
            ax_off.text(rect.get_x() + rect.get_width()/2, rect.get_height() + 0.5,
                        txt, ha="center", va="bottom", fontsize=9)
        ax_off.grid(True, axis="y", alpha=0.15)
        if args.p95_thresh:
            ax_off.axhline(args.p95_thresh, linestyle="--", linewidth=1.0, color="#555555")
    else:
        ax_off.axis("off")
        ax_off.text(0.5, 0.5, "No targets to rank for offenders", ha="center", va="center", fontsize=11)

    # Robust spacing (no tight_layout overlap)
    fig.subplots_adjust(top=0.88, hspace=0.50, wspace=0.28)
    plt.savefig(args.out, dpi=140, bbox_inches="tight")
    print(f"[OK] Saved executive report -> {args.out}")

if __name__ == "__main__":
    main()
