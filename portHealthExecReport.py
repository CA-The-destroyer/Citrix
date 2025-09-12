#!/usr/bin/env python3
# portHealthExecReport.py — Executive PNG for TCP ports (KPI + p95 trend + offenders)
#
# What it does:
#   • Discovers sr_trend_YYYY-MM-DD[_PORT].csv in the current directory (or --csv-dir)
#   • Prompts you to pick one (auto-picks most recent in non-interactive mode)
#   • Infers --port-filter from filename suffix if not provided
#   • Saves PNG to: ./exec_<port-or-all>_<YYYY-MM-DD>_<HHMMZ>.png (unless --out is given)
#
# Dependencies:
#   • matplotlib
#   • stdlib: argparse, csv, datetime, os, math, collections, sys, re

import argparse, csv, datetime as dt, os, math, collections, sys, re
import matplotlib
import matplotlib.dates as mdates

DATEFMT="%Y-%m-%d"
THRESH_OK=99.0
THRESH_P95=50.0
FN_RX = re.compile(r"^sr_trend_(\d{4}-\d{2}-\d{2})(?:_(\d{1,5}))?\.csv$")

def parse_ts(s):
    try: ts=dt.datetime.fromisoformat(s.replace("Z","+00:00"))
    except: ts=dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None: ts=ts.replace(tzinfo=dt.timezone.utc)
    return ts

def percentile(sorted_vals, p):
    if not sorted_vals: return math.nan
    n=len(sorted_vals)
    if n==1: return float(sorted_vals[0])
    idx=max(0,min(n-1,int(round((p/100.0)*(n-1)))))
    return float(sorted_vals[idx])

def find_csvs(csv_dir):
    items=[]
    for name in os.listdir(csv_dir):
        m=FN_RX.match(name)
        if not m: continue
        date_s, port_s = m.group(1), m.group(2)
        try: ts = dt.datetime.strptime(date_s, "%Y-%m-%d")
        except: ts = dt.datetime.min
        port = int(port_s) if port_s else None
        full=os.path.join(csv_dir,name)
        mtime=os.path.getmtime(full)
        items.append({"path":full,"name":name,"date":date_s,"port":port,"ts":ts,"mtime":mtime})
    items.sort(key=lambda x:(x["ts"], x["port"] if x["port"] is not None else -1, x["mtime"]), reverse=True)
    return items

def prompt(items):
    if not sys.stdin.isatty() or len(items)<=1:
        ch = items[0] if items else None
        if ch: print(f"[INFO] Selected CSV: {ch['name']}")
        return ch
    print("Select dataset for Executive Report:")
    for i,it in enumerate(items,1):
        ps=f" port {it['port']}" if it["port"] is not None else ""
        print(f"  {i}. {it['name']} (date {it['date']}{ps})")
    sel=input("Enter number [1]: ").strip() or "1"
    try:
        idx=int(sel)
        if 1<=idx<=len(items): return items[idx-1]
    except: pass
    print("[WARN] Invalid choice, defaulting to #1.")
    return items[0]

def load_rows(csv_path):
    with open(csv_path,"r",encoding="utf-8") as f:
        r=csv.DictReader(f)
        has_src="src_ip" in (r.fieldnames or [])
        has_dst="dst_ip" in (r.fieldnames or [])
        for row in r:
            try:
                ts=parse_ts(row["timestamp_utc"])
                ep=row["endpoint"]
                port=int(row.get("port","0") or 0)
                lat=float(row["latency_ms"])
                ok=(row["success"] in ("1","True","true"))
                src=row.get("src_ip","") if has_src else ""
                dst=row.get("dst_ip","") if has_dst else ""
                yield {"ts":ts,"endpoint":ep,"port":port,"lat":lat,"ok":ok,"src":src,"dst":dst}
            except: continue

def bucket_minute(ts): return ts.replace(second=0, microsecond=0)
def fmt_ms(x): return "—" if (x is None or math.isnan(x)) else (f"{x:.1f} ms" if x<1000 else f"{x/1000:.2f} s")

def main():
    ap=argparse.ArgumentParser(description="Exec PNG for TCP ports")
    ap.add_argument("--csv", help="Explicit CSV path (overrides discovery)")
    ap.add_argument("--csv-dir", default=".", help="Directory to discover CSVs (default: .)")
    ap.add_argument("--minutes", type=int, default=60)
    ap.add_argument("--endpoint", action="append", help="Filter to endpoint(s)")
    ap.add_argument("--port-filter", type=int, help="Only include this TCP port from CSV (optional)")
    ap.add_argument("--out", help="Output PNG (default ./exec_<port-or-all>_<YYYY-MM-DD>_<HHMMZ>Z.png)")
    ap.add_argument("--topn", type=int, default=8)
    ap.add_argument("--ok-thresh", type=float, default=THRESH_OK)
    ap.add_argument("--p95-thresh", type=float, default=THRESH_P95)
    ap.add_argument("--trend-by", choices=["overall","endpoint","route"], default="overall")
    ap.add_argument("--trend-max-series", type=int, default=8)
    args=ap.parse_args()

    if not os.environ.get("DISPLAY"): matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Select CSV
    if args.csv:
        choice={"path":args.csv,"name":os.path.basename(args.csv),"date":"","port":None}
    else:
        items=find_csvs(args.csv_dir)
        if not items: raise SystemExit("[ERROR] No sr_trend_*.csv files found here.")
        choice=prompt(items)

    csv_path = choice["path"]
    date_hint = choice.get("date", "")         # YYYY-MM-DD from filename
    inferred_port = choice.get("port", None)   # port suffix if present

    # Port filter defaulted from filename if not supplied
    if args.port_filter is None and inferred_port is not None:
        args.port_filter = inferred_port

    # Timestamped default output
    now_utc = dt.datetime.now(dt.timezone.utc).strftime("%H%M")
    date_part = date_hint or "unknown-date"
    port_part = args.port_filter if args.port_filter is not None else "all"
    out_path = args.out or f"./exec_{port_part}_{date_part}_{now_utc}Z.png"

    rows=list(load_rows(csv_path))
    if args.endpoint:
        allowed=set(args.endpoint); rows=[r for r in rows if r["endpoint"] in allowed]
    if args.port_filter is not None:
        rows=[r for r in rows if r["port"] == args.port_filter]
    if not rows: raise SystemExit("[INFO] No matching data.")

    # Window: last N minutes from 'now'
    now=dt.datetime.now(dt.timezone.utc)
    start=now - dt.timedelta(minutes=args.minutes)
    rows=[r for r in rows if r["ts"] >= start]
    if not rows: raise SystemExit("[INFO] No samples in window.")

    total=len(rows)
    okc=sum(1 for r in rows if r["ok"])
    okpct=(okc/total)*100.0
    lats=sorted([r["lat"] for r in rows if r["ok"] and not math.isnan(r["lat"])])
    def pctl(v, p): return v[int(round((p/100.0)*(len(v)-1)))] if v else math.nan
    p50=pctl(lats,50); p95=pctl(lats,95)
    fails=total-okc

    def tkey(r):
        if args.trend_by=="overall": return "overall"
        if args.trend_by=="endpoint": return r["endpoint"]
        return f"{r.get('src','')}→{r.get('dst','') or r['endpoint']}"

    bins_by=collections.defaultdict(lambda: collections.defaultdict(list))
    for r in rows:
        if r["ok"] and not math.isnan(r["lat"]):
            g=tkey(r); bins_by[g][bucket_minute(r["ts"])].append(r["lat"])

    series={}
    for g,b in bins_by.items():
        xs,ys=[],[]
        for t in sorted(b.keys()):
            sv=sorted(b[t]); xs.append(mdates.date2num(t)); ys.append(pctl(sv,95))
        if xs: series[g]=(xs,ys)
    if args.trend_by!="overall" and len(series)>args.trend_max_series:
        ranked=[]
        for g,(xs,ys) in series.items():
            last=ys[-1] if ys else float("nan")
            ranked.append((g, last if not math.isnan(last) else -1.0))
        ranked.sort(key=lambda t: t[1], reverse=True)
        keep=set(g for g,_ in ranked[:args.trend_max_series])
        series={g:v for g,v in series.items() if g in keep}

    glats=collections.defaultdict(list)
    gok=collections.defaultdict(lambda:[0,0])
    for r in rows:
        key=(r["endpoint"], r.get("src",""), r.get("dst","") or r["endpoint"])
        gok[key][1]+=1
        if r["ok"]:
            gok[key][0]+=1; glats[key].append(r["lat"])
    offenders=[]
    for key,l in glats.items():
        ep,src,dst=key; sv=sorted(l); gp95=pctl(sv,95)
        oks,tot=gok[key]; opct=(oks/tot)*100.0 if tot else 0.0
        offenders.append((ep,src,dst,gp95,opct,tot))
    for key,(oks,tot) in gok.items():
        if key not in glats:
            ep,src,dst=key; opct=(oks/tot)*100.0 if tot else 0.0
            offenders.append((ep,src,dst,math.nan,opct,tot))
    offenders.sort(key=lambda x: (x[4], -(x[3] if not math.isnan(x[3]) else -1)))
    offenders=offenders[:args.topn]

    fig=plt.figure(figsize=(14,8))
    gs=fig.add_gridspec(3,2, height_ratios=[1.2,1.6,1.8], width_ratios=[1,1], hspace=0.52, wspace=0.30)
    title_suffix = f" (port {args.port_filter})" if args.port_filter is not None else ""
    fig.suptitle(f"TCP Executive Assessment{title_suffix}", fontsize=16, fontweight="bold", y=0.992)

    axk=fig.add_subplot(gs[0,0]); axk.axis("off")
    kpi_y=0.88; lh=0.16
    def ok_style(v): return "#2e7d32" if v>=args.ok_thresh else ("#ef6c00" if v>=max(95.0,args.ok_thresh-2.0) else "#c62828")
    def p95_style(v):
        if math.isnan(v): return "#ef6c00"
        if v<=args.p95_thresh: return "#2e7d32"
        if v<=args.p95_thresh*2: return "#ef6c00"
        return "#c62828"
    axk.text(0.00,kpi_y, "Total connects:", fontsize=12)
    axk.text(0.40,kpi_y, f"{total:,}", fontsize=12)
    axk.text(0.62,kpi_y, "OK%:", fontsize=12)
    axk.text(0.78,kpi_y, f"{okpct:.1f}%", fontsize=12, color=ok_style(okpct))
    axk.text(0.00,kpi_y-lh, "Failures:", fontsize=12)
    axk.text(0.40,kpi_y-lh, f"{fails:,}", fontsize=12, color="#c62828")
    axk.text(0.62,kpi_y-lh, "p50:", fontsize=12)
    axk.text(0.78,kpi_y-lh, fmt_ms(p50), fontsize=12, color=p95_style(p50))
    axk.text(0.62,kpi_y-2*lh, "p95:", fontsize=12)
    axk.text(0.78,kpi_y-2*lh, fmt_ms(p95), fontsize=12, color=p95_style(p95))

    axt=fig.add_subplot(gs[0,1]); axt.axis("off")
    port_text = f" | Port: {args.port_filter}" if args.port_filter is not None else ""
    axt.text(0.0,0.98, f"Window: last {args.minutes} min   |   Dataset: {date_hint or os.path.basename(csv_path)}   |   Trend by: {args.trend_by}{port_text}",
             fontsize=10, va="top")
    axt.text(0.0,0.72,"Thresholds", fontsize=12, fontweight="bold", va="top")
    axt.text(0.0,0.52, f"OK% ≥ {args.ok_thresh:.1f}%  (green)\n"
                       f"p95 ≤ {args.p95_thresh:.1f} ms (green)\n"
                       f"Between = yellow; worse = red", fontsize=10, va="top")

    axtd=fig.add_subplot(gs[1,:])
    if series:
        if args.trend_by=="overall":
            xs,ys=next(iter(series.values())); axtd.plot(xs,ys,linewidth=1.8,label="p95 (per-minute)")
        else:
            for name in sorted(series.keys()):
                xs,ys=series[name]; axtd.plot(xs,ys,linewidth=1.6,label=name)
        axtd.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        if args.p95_thresh:
            axtd.axhline(args.p95_thresh, linestyle="--", linewidth=1.2, color="#555555",
                         label=f"p95 threshold ({args.p95_thresh:.1f} ms)")
        suf="" if args.trend_by=="overall" else f" — {args.trend_by}"
        axtd.set_title(f"p95 Trend (per minute){suf}", fontsize=12)
        axtd.set_ylabel("Latency (ms)"); axtd.grid(True, axis="y", alpha=0.25)
        axtd.legend(loc="upper right", fontsize=9)
    else:
        axtd.axis("off"); axtd.text(0.5,0.5,"Not enough OK samples", ha="center", va="center", fontsize=11)

    axo=fig.add_subplot(gs[2,:])
    if offenders:
        labels=[]; vals=[]; cols=[]; ann=[]
        for (ep,src,dst,p95g,okg,tot) in offenders:
            route=f"{src}→{dst}" if (src or dst) else "route n/a"
            labels.append(f"{ep}  [{route}]")
            vals.append(0.0 if math.isnan(p95g) else p95g)
            col="#2e7d32"
            if math.isnan(p95g) or p95g>args.p95_thresh or okg<args.ok_thresh:
                col = "#c62828" if (okg<args.ok_thresh or math.isnan(p95g)) else "#ef6c00"
            cols.append(col); ann.append(f"{okg:.1f}%")
        x=range(len(labels)); bars=axo.bar(x, vals, color=cols)
        axo.set_ylabel("p95 (ms)")
        axo.set_title(f"Worst Endpoints by p95 (Top {len(labels)}) — labels show OK% (route-aware)", fontsize=12)
        def trim(s): return s if len(s)<=48 else s[:45]+"…"
        axo.set_xticks(x); axo.set_xticklabels([trim(s) for s in labels], rotation=12, ha="right")
        for rect,txt in zip(bars, ann):
            axo.text(rect.get_x()+rect.get_width()/2, rect.get_height()+0.5, txt,
                     ha="center", va="bottom", fontsize=9)
        axo.grid(True, axis="y", alpha=0.15)
        if args.p95_thresh: axo.axhline(args.p95_thresh, linestyle="--", linewidth=1.0, color="#555555")
    else:
        axo.axis("off"); axo.text(0.5,0.5,"No endpoints to rank", ha="center", va="center", fontsize=11)

    fig.subplots_adjust(top=0.88, hspace=0.52, wspace=0.30)
    out_dir = os.path.dirname(out_path) or "."
    if out_dir and out_dir not in (".", ""): os.makedirs(out_dir, exist_ok=True)
    plt.savefig(out_path, dpi=140, bbox_inches="tight")
    print(f"[OK] Saved executive report -> {out_path}")

if __name__=="__main__":
    main()
