#!/usr/bin/env python3
# DNSHealthExecReport.py — Executive-friendly DNS health report (PNG)
# Inputs: DNSHealthChk.csv (today's UTC by default)
# Outputs: Single PNG with KPIs, trend, and "worst offenders" bars
#
# Deps: matplotlib (no pandas/numpy)
#
# KPIs shown over a time window (default last 60 minutes):
#   - Total queries, OK%
#   - p50 / p95 latency
#   - Fail count
# Trend:
#   - Overall p95 per minute (with threshold line)
# Offenders:
#   - Top targets by p95 (bars), annotated with OK%

import argparse, csv, datetime as dt, os, math, collections
import matplotlib
import matplotlib.dates as mdates

DATEFMT = "%Y-%m-%d"

# Executive thresholds — tune as needed
THRESH_OK = 95.0   # %
THRESH_P95 = 10.0  # ms (internal LAN target)

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
    """Yield dict rows with parsed fields needed for this report."""
    with open(csv_path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                ts = parse_ts(row["timestamp_utc"])
                resolver = row["resolver"]
                target = f'{row["query"]}({row["type"]})'
                lat = float(row["latency_ms"])
                ok = (row["rcode"] == "NOERROR") and (row["success"] in ("1","True","true"))
                yield {"ts": ts, "resolver": resolver, "target": target,
                       "lat": lat, "ok": ok}
            except Exception:
                continue

def bucket_minute(ts: dt.datetime) -> dt.datetime:
    return ts.replace(second=0, microsecond=0)

def main():
    ap = argparse.ArgumentParser(description="Executive PNG for DNS Health (p95 trend + top offenders)")
    ap.add_argument("--csv-dir", required=True, help="Folder with dns_trend_YYYY-MM-DD.csv")
    ap.add_argument("--date", default=dt.datetime.now(dt.timezone.utc).strftime(DATEFMT),
                    help="UTC date (YYYY-MM-DD). Default: today")
    ap.add_argument("--minutes", type=int, default=60,
                    help="Lookback window in minutes (default 60)")
    ap.add_argument("--resolver", action="append",
                    help="Filter to one or more resolvers (repeatable). Default: all")
    ap.add_argument("--out", required=True, help="PNG output path (headless-safe)")
    ap.add_argument("--topn", type=int, default=8, help="Show top-N offending targets (default 8)")
    ap.add_argument("--ok-thresh", type=float, default=THRESH_OK, help="OK%% threshold for green/yellow/red")
    ap.add_argument("--p95-thresh", type=float, default=THRESH_P95, help="p95 threshold in ms")
    args = ap.parse_args()

    # Headless backend if needed
    if not os.environ.get("DISPLAY"):
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # import after backend set

    csv_path = os.path.join(args.csv_dir, f"dns_trend_{args.date}.csv")
    if not os.path.exists(csv_path):
        raise SystemExit(f"[ERROR] Not found: {csv_path}")

    rows = list(load_rows(csv_path))
    if args.resolver:
        allowed = set(args.resolver)
        rows = [r for r in rows if r["resolver"] in allowed]

    if not rows:
        raise SystemExit("[INFO] No matching data in file.")

    # Time filter: last N minutes
    now = dt.datetime.now(dt.timezone.utc)
    start_ts = now - dt.timedelta(minutes=args.minutes)
    rows = [r for r in rows if r["ts"] >= start_ts]

    if not rows:
        raise SystemExit("[INFO] No samples in the last window; try a larger --minutes or check time/date.")

    # ---------- KPIs over window ----------
    total = len(rows)
    ok_count = sum(1 for r in rows if r["ok"])
    ok_pct = (ok_count / total) * 100.0
    lats_all = sorted([r["lat"] for r in rows if r["ok"] and not math.isnan(r["lat"])])
    p50 = percentile(lats_all, 50)
    p95 = percentile(lats_all, 95)
    fail_count = total - ok_count

    # ---------- Trend: per-minute p95 over the window ----------
    minute_bins = collections.defaultdict(list)
    for r in rows:
        if r["ok"] and not math.isnan(r["lat"]):
            minute_bins[bucket_minute(r["ts"])].append(r["lat"])

    trend_x = []
    trend_p95 = []
    if minute_bins:
        for t in sorted(minute_bins.keys()):
            sv = sorted(minute_bins[t])
            trend_x.append(mdates.date2num(t))
            trend_p95.append(percentile(sv, 95))

    # ---------- Offenders: top-N targets by p95 (with OK%) ----------
    per_target_lats = collections.defaultdict(list)
    per_target_ok = collections.defaultdict(lambda: [0,0])  # [ok, total]
    for r in rows:
        per_target_ok[r["target"]][1] += 1
        if r["ok"]:
            per_target_ok[r["target"]][0] += 1
            if not math.isnan(r["lat"]):
                per_target_lats[r["target"]].append(r["lat"])

    offenders = []
    for t, l in per_target_lats.items():
        sv = sorted(l)
        targ_p95 = percentile(sv, 95)
        oks, tot = per_target_ok[t]
        opct = (oks/tot)*100.0 if tot else 0.0
        offenders.append((t, targ_p95, opct, tot))
    # If a target has zero OK rows (all failures), include it with p95=NaN but sort to top by OK%
    for t, (oks, tot) in per_target_ok.items():
        if t not in per_target_lats:
            offenders.append((t, math.nan, (oks/tot)*100.0 if tot else 0.0, tot))

    # Sort primarily by OK% ascending, then by p95 descending (NaNs last)
    offenders.sort(key=lambda x: (x[2], -(x[1] if not math.isnan(x[1]) else -1)))
    offenders = offenders[:args.topn]

    # ---------- Figure layout ----------
    fig = plt.figure(figsize=(14, 8))
    gs = fig.add_gridspec(3, 2, height_ratios=[1.2, 1.5, 1.5], width_ratios=[1,1], hspace=0.4, wspace=0.25)

    # KPI panel (top-left)
    ax_kpi = fig.add_subplot(gs[0, 0])
    ax_kpi.axis("off")

    def colorize(val, good_cond):
        # green if good_cond True; yellow if borderline; red if bad
        try:
            v = float(val)
        except:  # NaN handling
            return f"{val}"
        if good_cond(v) == "good":
            return f"$\\bf{{{v:.1f}}}$"
        if good_cond(v) == "warn":
            return f"{v:.1f}"
        return f"{v:.1f}"

    # Determine styles
    def ok_style(v):
        if v >= args.ok_thresh: return "good"
        if v >= max(90.0, args.ok_thresh - 5.0): return "warn"
        return "bad"

    def p95_style(v):
        if math.isnan(v): return "warn"
        if v <= args.p95_thresh: return "good"
        if v <= args.p95_thresh * 2: return "warn"
        return "bad"

    # Nice headings
    ax_kpi.text(0.0, 0.95, "DNS Health — Executive Summary", fontsize=14, fontweight="bold", va="top")
    ax_kpi.text(0.0, 0.80, f"Window: last {args.minutes} min   |   Dataset: {args.date} UTC", fontsize=10)

    # KPI grid
    kpi_y = 0.60
    line_h = 0.13

    # Total / OK% / Fail
    ax_kpi.text(0.00, kpi_y,       "Total queries:", fontsize=12)
    ax_kpi.text(0.35, kpi_y,       f"{total:,}", fontsize=12)
    ax_kpi.text(0.60, kpi_y,       "OK%:", fontsize=12)
    ok_style_val = ok_style(ok_pct)
    ok_text = f"{ok_pct:.1f}%"
    ax_kpi.text(0.75, kpi_y,       ok_text,
                fontsize=12, color=("#2e7d32" if ok_style_val=="good" else "#ef6c00" if ok_style_val=="warn" else "#c62828"))

    ax_kpi.text(0.00, kpi_y - line_h, "Failures:", fontsize=12)
    ax_kpi.text(0.35, kpi_y - line_h, f"{fail_count:,}", fontsize=12, color=("#c62828" if fail_count>0 else "#2e7d32"))

    # p50 / p95
    def fmt_ms(x):
        if x is None or math.isnan(x): return "—"
        return f"{x:.1f} ms" if x < 1000 else f"{x/1000:.2f} s"

    p95_style_val = p95_style(p95)
    p50_style_val = p95_style(p50)  # use same thresholds for simplicity

    ax_kpi.text(0.60, kpi_y - line_h, "p50:", fontsize=12)
    ax_kpi.text(0.75, kpi_y - line_h, fmt_ms(p50),
                fontsize=12, color=("#2e7d32" if p50_style_val=="good" else "#ef6c00" if p50_style_val=="warn" else "#c62828"))

    ax_kpi.text(0.60, kpi_y - 2*line_h, "p95:", fontsize=12)
    ax_kpi.text(0.75, kpi_y - 2*line_h, fmt_ms(p95),
                fontsize=12, color=("#2e7d32" if p95_style_val=="good" else "#ef6c00" if p95_style_val=="warn" else "#c62828"))

    # Threshold box (top-right)
    ax_th = fig.add_subplot(gs[0, 1])
    ax_th.axis("off")
    ax_th.text(0.0, 0.95, "Thresholds", fontsize=12, fontweight="bold", va="top")
    ax_th.text(0.0, 0.75, f"OK% ≥ {args.ok_thresh:.1f}%  (green)\n"
                          f"p95 ≤ {args.p95_thresh:.1f} ms (green)\n"
                          f"Between = yellow; worse = red", fontsize=10, va="top")

    # Trend panel (middle row spans both columns)
    ax_tr = fig.add_subplot(gs[1, :])
    if trend_x and trend_p95:
        ax_tr.plot(trend_x, trend_p95, linewidth=1.8, label="p95 (per-minute)")
        ax_tr.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        if args.p95_thresh:
            ax_tr.axhline(args.p95_thresh, linestyle="--", linewidth=1.2, color="#555555", label=f"p95 threshold ({args.p95_thresh:.1f} ms)")
        ax_tr.set_title("p95 Trend (per minute)", fontsize=12)
        ax_tr.set_ylabel("Latency (ms)")
        ax_tr.grid(True, axis="y", alpha=0.25)
        ax_tr.legend(loc="upper right", fontsize=9)
    else:
        ax_tr.axis("off")
        ax_tr.text(0.5, 0.5, "Not enough OK samples for per-minute p95 trend", ha="center", va="center", fontsize=11)

    # Offenders panel (bottom row spans both columns)
    ax_off = fig.add_subplot(gs[2, :])
    if offenders:
        labels = []
        vals = []
        colors = []
        ann = []   # OK% annotations
        for (t, p95_t, okpct_t, tot_t) in offenders:
            labels.append(t)
            # For all-failure targets (NaN p95), plot as 0 but color red and annotate
            v = 0.0 if math.isnan(p95_t) else p95_t
            vals.append(v)
            # color by p95 threshold and OK%
            col = "#2e7d32"
            if math.isnan(p95_t) or p95_t > args.p95_thresh or okpct_t < args.ok_thresh:
                if okpct_t < args.ok_thresh or math.isnan(p95_t):
                    col = "#c62828"  # red if OK% bad or no OK points
                else:
                    col = "#ef6c00"  # yellow if p95 over but OK% fine
            colors.append(col)
            ann.append(f"{okpct_t:.1f}%")

        x = range(len(labels))
        bars = ax_off.bar(x, vals, color=colors)
        ax_off.set_ylabel("p95 (ms)")
        ax_off.set_title(f"Worst Targets by p95 (Top {len(labels)}) — labels show OK%", fontsize=12)
        ax_off.set_xticks(x)
        ax_off.set_xticklabels([s if len(s) <= 30 else s[:27]+"…" for s in labels], rotation=15, ha="right")
        # annotate OK% above bars
        for rect, txt in zip(bars, ann):
            ax_off.text(rect.get_x() + rect.get_width()/2, rect.get_height() + 0.5, txt, ha="center", va="bottom", fontsize=9)
        ax_off.grid(True, axis="y", alpha=0.15)
        if args.p95_thresh:
            ax_off.axhline(args.p95_thresh, linestyle="--", linewidth=1.0, color="#555555")
    else:
        ax_off.axis("off")
        ax_off.text(0.5, 0.5, "No targets to rank for offenders", ha="center", va="center", fontsize=11)

    fig.suptitle("DNS Executive Assessment", fontsize=16, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(args.out, dpi=140)
    print(f"[OK] Saved executive report -> {args.out}")

if __name__ == "__main__":
    main()
