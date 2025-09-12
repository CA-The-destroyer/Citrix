#!/usr/bin/env python3
# portHealthViz.py — live console dashboard for TCP ports (route-aware + per-series thresholds)
#
# Dependencies (stdlib only): argparse, csv, datetime, os, time, collections, math, json, re, sys, tty
# Reads CSVs produced by portHealthChk.py:
#   sr_trend_YYYY-MM-DD.csv              (no port suffix)
#   sr_trend_YYYY-MM-DD_<port>.csv       (with port suffix)

import argparse, csv, datetime as dt, os, time, collections, math, json, re, sys

DATEFMT = "%Y-%m-%d"
GLOBAL_THRESH_OK = 99.0
GLOBAL_THRESH_P95 = 50.0

KEY_W, N_W, OK_W, P50_W, P95_W, LAST_W, AGE_W, THR_W, MEAN_W = 60, 5, 7, 8, 8, 8, 6, 3, 8

FN_RX = re.compile(r"^sr_trend_(\d{4}-\d{2}-\d{2})(?:_(\d{1,5}))?\.csv$")

def color(s, c): return f"\033[{c}m{s}\033[0m"
def red(s): return color(s, "31")
def yellow(s): return color(s, "33")
def green(s): return color(s, "32")
def clear(): os.system("cls" if os.name == "nt" else "clear")

def list_csvs(csv_dir: str):
    items=[]
    for name in os.listdir(csv_dir):
        m = FN_RX.match(name)
        if not m: continue
        date_s, port_s = m.group(1), m.group(2)
        try: ts = dt.datetime.strptime(date_s, "%Y-%m-%d")
        except: ts = dt.datetime.min
        port = int(port_s) if port_s else None
        full = os.path.join(csv_dir, name)
        mtime = os.path.getmtime(full)
        items.append({"path": full, "date": date_s, "port": port, "mtime": mtime, "name": name, "ts": ts})
    items.sort(key=lambda x: (x["ts"], x["port"] if x["port"] is not None else -1, x["mtime"]), reverse=True)
    return items

def prompt_select(items):
    # Non-interactive or single choice → auto-select
    if not sys.stdin.isatty() or len(items) <= 1:
        choice = items[0] if items else None
        if choice:
            print(f"[INFO] Selected CSV: {choice['name']}")
        return choice
    # Menu
    print("Select data source:")
    for i, it in enumerate(items, 1):
        ps = f" port {it['port']}" if it["port"] is not None else ""
        print(f"  {i}. {it['name']}  (date {it['date']}{ps})")
    sel = input(f"Enter number [1]: ").strip() or "1"
    try:
        idx = int(sel)
        if 1 <= idx <= len(items): return items[idx-1]
    except: pass
    print("[WARN] Invalid choice, defaulting to #1.")
    return items[0]

def tail_csv(path, start_pos):
    if not os.path.exists(path): return start_pos, []
    with open(path, "r", encoding="utf-8") as f:
        f.seek(start_pos); lines = f.readlines(); new_pos = f.tell()
    rows = []
    for i, line in enumerate(lines):
        if not line.strip(): continue
        if start_pos == 0 and i == 0 and line.lower().startswith("timestamp_utc"): continue
        rows.append(line)
    return new_pos, rows

def parse_ts(s):
    try:
        ts = dt.datetime.fromisoformat(s.replace("Z","+00:00"))
    except Exception:
        ts = dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None: ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts

def parse_row(line):
    # timestamp_utc,endpoint,port,success,latency_ms,error,src_ip,dst_ip
    r = next(csv.reader([line]))
    while len(r) < 8: r.append("")
    ts, endpoint, port, success, lat_ms, err, src, dst = r[:8]
    ts = parse_ts(ts)
    try: port_i = int(port or 0)
    except: port_i = 0
    try: lat = float(lat_ms)
    except: lat = math.nan
    ok = (success in ("1","True","true"))
    return ts, endpoint, port_i, ok, lat, err, src, dst

def fmt_ms_fixed(x, w):
    if x is None or (isinstance(x,float) and math.isnan(x)): return f"{'—':>{w}}"
    if x < 1000: return f"{int(round(x)):>{w-2}}ms"
    return f"{x/1000:>{w-1}.2f}s"

def fmt_pct_fixed(x, w):
    if x is None or (isinstance(x,float) and math.isnan(x)): return f"{'—':>{w}}"
    return f"{x:>{w-1}.1f}%"

def percentile(arr, p):
    if not arr: return None
    a = sorted(arr); k = max(0, min(len(a)-1, int(round((p/100.0)*(len(a)-1)))))
    return a[k]

def compile_rules(inline_rules, rules_file):
    rules=[]
    if rules_file:
        with open(rules_file,"r",encoding="utf-8") as f: data=json.load(f)
        for obj in data:
            pat=obj.get("pattern",""); ok=obj.get("ok_pct"); p95=obj.get("p95_ms")
            if not pat or (ok is None and p95 is None): continue
            try: rules.append({"regex":re.compile(pat), "ok":ok, "p95":p95, "raw":pat})
            except re.error: pass
    for raw in inline_rules or []:
        pat=ok=p95=None
        for part in [p.strip() for p in re.split(r"[;,]", raw) if p.strip()]:
            if part.lower().startswith("pattern="): pat=part.split("=",1)[1].strip()
            elif part.lower().startswith(("ok=","ok_pct=")):
                try: ok=float(part.split("=",1)[1].strip())
                except: pass
            elif part.lower().startswith(("p95=","p95_ms=")):
                try: p95=float(part.split("=",1)[1].strip())
                except: pass
        if pat and (ok is not None or p95 is not None):
            try: rules.append({"regex":re.compile(pat),"ok":ok,"p95":p95,"raw":pat})
            except re.error: pass
    return rules

def main():
    ap=argparse.ArgumentParser(description="Console TCP dashboard (route-aware, rules, aligned)")
    ap.add_argument("--csv", help="Explicit CSV path (overrides discovery)")
    ap.add_argument("--csv-dir", default=".", help="Directory to discover CSVs (default: .)")
    ap.add_argument("--window", type=int, default=300)
    ap.add_argument("--group-by-route", action="store_true", help="Group as endpoint [src->dst]")
    ap.add_argument("--refresh", type=float, default=2.0)
    ap.add_argument("--show-mean", action="store_true")
    ap.add_argument("--port-filter", type=int, help="Only include rows with this TCP port (optional)")
    ap.add_argument("--rule", action="append")
    ap.add_argument("--rules-file")
    ap.add_argument("--ok-thresh", type=float, default=GLOBAL_THRESH_OK)
    ap.add_argument("--p95-thresh", type=float, default=GLOBAL_THRESH_P95)
    args=ap.parse_args()

    # Discover/select CSV if not provided
    if args.csv:
        choice = {"path": args.csv, "name": os.path.basename(args.csv), "date": "", "port": None}
    else:
        items = list_csvs(args.csv_dir)
        if not items: raise SystemExit("[ERROR] No sr_trend_*.csv files found in this directory.")
        choice = prompt_select(items)

    path = choice["path"]
    date_hint = choice.get("date","")
    inferred_port = choice.get("port", None)

    # If user didn't pass port-filter, infer from filename suffix if present
    if args.port_filter is None and inferred_port is not None:
        args.port_filter = inferred_port

    rules=compile_rules(args.rule, args.rules_file)
    pos=0

    series=collections.defaultdict(lambda: collections.deque(maxlen=args.window))
    last_ts={}
    meta={}

    def key_of(endpoint, src, dst):
        if args.group_by_route:
            route=f"{src}->{dst}" if (src or dst) else "n/a"
            return f"{endpoint} [{route}]"
        return endpoint

    def apply_thr(k):
        if not rules or k not in meta: return args.ok_thresh, args.p95_thresh, None
        ctx=meta[k]
        s=f"{ctx['endpoint']} {ctx['route']}"
        for rule in rules:
            if rule["regex"].search(s):
                return rule["ok"] if rule["ok"] is not None else args.ok_thresh, \
                       rule["p95"] if rule["p95"] is not None else args.p95_thresh, rule["raw"]
        return args.ok_thresh, args.p95_thresh, None

    def ingest(lines):
        for line in lines:
            ts, ep, port_i, ok, lat, err, src, dst = parse_row(line)
            if args.port_filter is not None and port_i != args.port_filter:
                continue
            k=key_of(ep, src, dst)
            series[k].append((ts, 1 if ok else 0, lat))
            last_ts[k]=ts
            if k not in meta:
                meta[k]={"endpoint":ep,"route":f"{src}->{dst}" if (src or dst) else "n/a"}

    def summarize():
        rows=[]
        now=dt.datetime.now(dt.timezone.utc)
        for k,dq in series.items():
            if not dq: continue
            oks=[v[1] for v in dq]
            lats=[v[2] for v in dq if not (isinstance(v[2],float) and math.isnan(v[2]))]
            cnt=len(dq); ok_rate=(sum(oks)/cnt)*100.0 if cnt else 0.0
            p50=percentile(lats,50) if lats else None
            p95=percentile(lats,95) if lats else None
            mean=(sum(lats)/len(lats)) if lats else None
            last=next((v[2] for v in reversed(dq) if not (isinstance(v[2],float) and math.isnan(v[2]))), math.nan)
            age=(now - last_ts.get(k, now)).total_seconds()
            ok_thr, p95_thr, rule_raw = apply_thr(k)
            rows.append({"k":k,"cnt":cnt,"ok":ok_rate,"p50":p50,"p95":p95,"mean":mean,"last":last,"age":age,
                         "ok_thr":ok_thr,"p95_thr":p95_thr,"rule":rule_raw})
        rows.sort(key=lambda r: (r["ok"], -(r["p95"] if r["p95"] is not None else -1)))
        return rows

    while True:
        pos, lines = tail_csv(path, pos)
        if lines: ingest(lines)

        clear()
        pf = f"  Port filter: {args.port_filter}" if args.port_filter is not None else ""
        print(f"portHealthViz (TCP) | Source: {os.path.basename(path)}  DateHint: {date_hint}{pf}")
        print("Window:", args.window, "Refresh:", args.refresh, "s  UTC:",
              dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        print("Grouping:", "endpoint [src->dst]" if args.group_by_route else "endpoint")
        if rules: print(f"Rules: {len(rules)} loaded (first match wins)")
        sep="-"*(KEY_W+N_W+OK_W+P50_W+P95_W+LAST_W+AGE_W+THR_W+(MEAN_W if args.show_mean else 0)+12)
        print(sep)
        base_hdr=f"{{:<{KEY_W}}} {{:>{N_W}}} {{:>{OK_W}}} {{:>{P50_W}}} {{:>{P95_W}}} {{:>{LAST_W}}} {{:>{AGE_W}}} {{:>{THR_W}}}"
        hdr = base_hdr.format("Series (Endpoint[Route])","N","OK%","p50","p95","Last","Age","Thr")
        if args.show_mean:
            hdr += f" {{:>{MEAN_W}}}".format("Mean")
        print(hdr); print(sep)

        rows=summarize()
        if not rows:
            print("(waiting for data…)")
        else:
            for r in rows:
                k=r["k"][:KEY_W]
                n=f"{r['cnt']:>{N_W}d}"
                ok_str=f"{r['ok']:>{OK_W-1}.1f}%"
                p50=fmt_ms_fixed(r["p50"], P50_W)
                p95=fmt_ms_fixed(r["p95"], P95_W)
                last=fmt_ms_fixed(r["last"], LAST_W)
                age=f"{int(r['age']):>{AGE_W}d}s"
                thr=("*" if r["rule"] else "").rjust(THR_W)
                if r["ok"] < r["ok_thr"]: ok_str=red(ok_str)
                elif r["ok"] < 99.9: ok_str=yellow(ok_str)
                else: ok_str=green(ok_str)
                if r["p95"] is not None and r["p95"] > r["p95_thr"]: p95=red(p95)
                line=f"{k:<{KEY_W}} {n} {ok_str:>{OK_W}} {p50:>{P50_W}} {p95:>{P95_W}} {last:>{LAST_W}} {age:>{AGE_W}} {thr:>{THR_W}}"
                if args.show_mean:
                    mean=fmt_ms_fixed(r["mean"], MEAN_W)
                    if r["mean"] is not None and r["mean"] > r["p95_thr"]: mean=yellow(mean)
                    line+=f" {mean:>{MEAN_W}}"
                print(line)
        print(sep)
        print(f"Legend: OK% < thr → RED | p95 > thr → RED | Thr=* has custom rule")
        time.sleep(args.refresh)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: pass
