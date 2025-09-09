#!/usr/bin/env python3
# DNSHealthExecReport.py — Executive-friendly DNS health report (PNG)
# Route-aware offenders (target + src->dst), tuned layout (no overlap).
# Deps: matplotlib (no pandas/numpy).

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
    minute_bins = collections.defaultdict(list)
    for r in rows:
        if r["ok"] and not math.isnan(r["lat"]):
            minute_bins[bucket_minute(r["ts"])].append(r["lat"])
    trend_x, trend_p95 = [], []
    if minute_bins:
        for t in sorted(minute_bins.keys()):
            sv = sorted(minute_bins[t])
            trend_x.append(mdates.date2num(t))
            trend_p95.append(percentile(sv, 95))

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

    # Suptitle (moved up for spacing)
    fig.suptitle("DNS Executive Assessment (route-aware)", fontsize=16, fontweight="bold", y=0.995)

    # KPI panel (top-left) — shifted lower to avoid overlap with suptitle
    ax_kpi = fig.add_subplot(gs[0, 0]); ax_kpi.axis("off")
    ax_kpi.text(0.0, 0.90, "DNS Health — Executive Summary", fontsize=14, fontweight="bold", va="top")
   
