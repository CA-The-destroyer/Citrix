#!/usr/bin/env python3
# portHealthScatter.py — raw TCP connect latency scatter (no smoothing)
#
# What it does:
#   • Discovers sr_trend_YYYY-MM-DD[_PORT].csv in the current directory (or --csv-dir)
#   • Prompts you to pick one (auto-picks most recent in non-interactive mode)
#   • Infers --port-filter from filename suffix if not provided
#   • Saves PNG to: ./scatter_<port-or-all>_<YYYY-MM-DD>_<HHMMZ>.png (unless --out is given)
#
# Dependencies:
#   • matplotlib
#   • stdlib: argparse, csv, datetime, os, math, random, re, collections, sys

import argparse, csv, datetime as dt, os, math, random, re, sys
from collections import defaultdict
import matplotlib
import matplotlib.dates as mdates

DATEFMT="%Y-%m-%d"
FN_RX = re.compile(r"^sr_trend_(\d{4}-\d{2}-\d{2})(?:_(\d{1,5}))?\.csv$")

def parse_ts(s):
    try: ts=dt.datetime.fromisoformat(s.replace("Z","+00:00"))
    except: ts=dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None: ts=ts.replace(tzinfo=dt.timezone.utc)
    return ts

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
    print("Select dataset for Scatter Report:")
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
        if not r.fieldnames: return
        has_src="src_ip" in r.fieldnames; has_dst="dst_ip" in r.fieldnames
        for row in r:
            try:
                ts=parse_ts(row["timestamp_utc"])
                ep=row["endpoint"]; lat=float(row["latency_ms"])
                ok=(row["success"] in ("1","True","true"))
                port=int(row.get("port","0") or 0)
                src=row.get("src_ip","") if has_src else ""
                dst=row.get("dst_ip","") if has_dst else ""
                yield {"ts":ts,"endpoint":ep,"port":port,"lat":lat,"ok":ok,"src":src,"dst":dst}
            except: continue

def main():
    ap=argparse.ArgumentParser(description="Raw TCP scatter (PNG)")
    ap.add_argument("--csv", help="Explicit CSV path (overrides discovery)")
    ap.add_argument("--csv-dir", default=".", help="Directory to discover CSVs (default: .)")
    ap.add_argument("--group-by", choices=["endpoint","route","target"], default="endpoint")
    ap.add_argument("--endpoint", action="append")
    ap.add_argument("--route", action="append")
    ap.add_argument("--port-filter", type=int, help="Only include this TCP port from CSV (optional)")
    ap.add_argument("--match", help="Regex to filter endpoint names")
    ap.add_argument("--y-max", type=float)
    ap.add_argument("--threshold-ms", type=float)
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--dot-size", type=float, default=12.0)
    ap.add_argument("--max-facets", type=int, default=8)
    ap.add_argument("--title", default="TCP Raw Connect Latency")
    ap.add_argument("--out", help="Output PNG path (default ./scatter_<port-or-all>_<YYYY-MM-DD>_<HHMMZ>Z.png)")
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
    date_hint = choice.get("date","")
    inferred_port = choice.get("port",None)
    if args.port_filter is None and inferred_port is not None:
        args.port_filter=inferred_port

    # Timestamped default output
    now_utc = dt.datetime.now(dt.timezone.utc).strftime("%H%M")
    date_part = date_hint or "unknown-date"
    port_part = args.port_filter if args.port_filter is not None else "all"
    out_path = args.out or f"./scatter_{port_part}_{date_part}_{now_utc}Z.png"

    rows=list(load_rows(csv_path))
    if not rows: raise SystemExit("[INFO] No rows parsed.")

    # Filters
    if args.endpoint:
        allowed=set(args.endpoint); rows=[r for r in rows if r["endpoint"] in allowed]
    if args.route:
        want=set(args.route); rows=[r for r in rows if f"{r.get('src','')}→{r.get('dst','') or r['endpoint']}" in want]
    if args.port_filter is not None:
        rows=[r for r in rows if r["port"] == args.port_filter]
    if args.match:
        rx=re.compile(args.match); rows=[r for r in rows if rx.search(r["endpoint"])]

    if not rows: raise SystemExit("[INFO] No rows after filters.")

    def skey(r):
        if args.group_by=="route": return f"{r.get('src','')}→{r.get('dst','') or r['endpoint']}"
        elif args.group_by=="target": return r["endpoint"]
        return r["endpoint"]

    groups=defaultdict(list)
    for r in rows: groups[skey(r)].append(r)

    keys=sorted(groups.keys(), key=str)
    if len(keys)>args.max_facets:
        scored=[]
        for k in keys:
            g=groups[k]; cnt=len(g); has_fail=any(not x["ok"] for x in g)
            scored.append((k, has_fail, cnt))
        scored.sort(key=lambda t:(t[1],t[2]), reverse=True)
        keys=[k for k,_,_ in scored[:args.max_facets]]

    height=2.5*max(1,len(keys))+1.2
    fig, axes = plt.subplots(len(keys), 1, figsize=(14,height), sharex=True)
    if isinstance(axes, (list, tuple)): axes=list(axes)
    elif hasattr(axes, "flatten"): axes=axes.flatten().tolist()
    else: axes=[axes]

    COL_OK="#1565C0"; COL_FAIL="#C62828"

    for ax,key in zip(axes, keys):
        g=groups[key]; okx,oky, kox,koy=[],[],[],[]
        for r in g:
            x=mdates.date2num(r["ts"])
            y=r["lat"] + (random.uniform(-args.jitter,args.jitter) if args.jitter>0 else 0.0)
            if r["ok"]: okx.append(x); oky.append(y)
            else: kox.append(x); koy.append(y)
        if kox: ax.scatter(kox,koy, s=args.dot_size, alpha=0.9, marker="x", color=COL_FAIL, label="Fail")
        if okx: ax.scatter(okx,oky, s=args.dot_size, alpha=0.6, marker="o", color=COL_OK,   label="OK")
        if args.threshold_ms is not None:
            ax.axhline(args.threshold_ms, linestyle="--", linewidth=1.0, color="#555555")
        if args.y_max: ax.set_ylim(0,args.y_max)
        cnt=len(g); fails=sum(1 for r in g if not r["ok"]); okpct=100.0*(cnt-fails)/cnt if cnt else 0.0
        ax.set_title(f"{args.group_by}: {key}   |   N={cnt}, OK={okpct:.1f}%, Fails={fails}", fontsize=10)
        ax.set_ylabel("ms"); ax.grid(True, axis="y", alpha=0.18)

    axes[-1].set_xlabel("Time (UTC)")
    for ax in axes: ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    port_suffix = f" (port {args.port_filter})" if args.port_filter is not None else ""
    fig.suptitle(args.title + port_suffix, fontsize=14, fontweight="bold", y=0.995)
    fig.tight_layout(rect=[0,0,1,0.97])

    out_dir = os.path.dirname(out_path) or "."
    if out_dir and out_dir not in (".", ""): os.makedirs(out_dir, exist_ok=True)
    plt.savefig(out_path, dpi=140)
    print(f"[OK] Saved scatter -> {out_path}")

if __name__=="__main__":
    main()
