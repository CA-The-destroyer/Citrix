#!/usr/bin/env python3
# DNSHealthViz_console.py — console DNS dashboard with thresholds
# Stdlib only. Highlights rows if OK% < 95 or p95 > 10ms.

import argparse, csv, datetime as dt, os, time, collections, math, sys

DATEFMT = "%Y-%m-%d"

# --- Thresholds (tune to your environment) ---
THRESH_OK = 95.0    # percent
THRESH_P95 = 10.0   # ms

# --- ANSI color helpers ---
def color(s, code): return f"\033[{code}m{s}\033[0m"
def red(s): return color(s, "31")
def yellow(s): return color(s, "33")
def green(s): return color(s, "32")

def latest_csv(csv_dir: str) -> str:
    return os.path.join(csv_dir, f"dns_trend_{dt.datetime.now(dt.timezone.utc).strftime(DATEFMT)}.csv")

def tail_csv(path: str, start_pos: int):
    if not os.path.exists(path): return start_pos, []
    with open(path, "r", encoding="utf-8") as f:
        f.seek(start_pos)
        lines = f.readlines()
        new_pos = f.tell()
    rows = []
    for i, line in enumerate(lines):
        if not line.strip(): continue
        if start_pos == 0 and i == 0 and line.lower().startswith("timestamp_utc"):
            continue  # skip header
        rows.append(line)
    return new_pos, rows

def parse_row(line: str):
    r = next(csv.reader([line]))
    while len(r) < 11: r.append("")
    ts_iso, resolver, qname, rtype, success, latency_ms, rcode, answers, ttl, used_tcp, err = r[:11]
    try: ts = dt.datetime.fromisoformat(ts_iso.replace("Z","+00:00"))
    except: ts = dt.datetime.now(dt.timezone.utc)
    if ts.tzinfo is None: ts = ts.replace(tzinfo=dt.timezone.utc)
    try: lat = float(latency_ms)
    except: lat = math.nan
    ok = (rcode == "NOERROR") and (success in ("1","True","true"))
    return ts, resolver, qname, rtype, ok, lat, rcode

def clear_console():
    os.system("cls" if os.name=="nt" else "clear")

def fmt_ms(x):
    if x is None or math.isnan(x): return "—"
    return f"{x:.0f}ms" if x<1000 else f"{x/1000:.2f}s"

def percentile(arr, p):
    if not arr: return None
    a = sorted(arr); k = max(0,min(len(a)-1,int(round((p/100)*(len(a)-1)))))
    return a[k]

def main():
    ap = argparse.ArgumentParser(description="Console DNS dashboard with thresholds")
    ap.add_argument("--csv-dir", required=True, help="Directory where DNSHealthChk writes CSVs")
    ap.add_argument("--window", type=int, default=300)
    ap.add_argument("--group-by-target", action="store_true")
    ap.add_argument("--refresh", type=float, default=2.0)
    args = ap.parse_args()

    current_day = dt.datetime.now(dt.timezone.utc).strftime(DATEFMT)
    csv_path = latest_csv(args.csv_dir)
    file_pos = 0

    series = collections.defaultdict(lambda: collections.deque(maxlen=args.window))
    last_ts = {}

    def key_of(resolver,qname,rtype):
        return (resolver,f"{qname}({rtype})") if args.group_by_target else resolver

    def roll_if_new_day():
        nonlocal current_day,csv_path,file_pos
        today = dt.datetime.now(dt.timezone.utc).strftime(DATEFMT)
        if today!=current_day:
            current_day=today; csv_path=latest_csv(args.csv_dir); file_pos=0

    def ingest(lines):
        for line in lines:
            ts,resolver,qname,rtype,ok,lat,rcode = parse_row(line)
            k = key_of(resolver,qname,rtype)
            series[k].append((ts,1 if ok else 0,lat))
            last_ts[k]=ts

    def summarize():
        now = dt.datetime.now(dt.timezone.utc)
        rows=[]
        for k,dq in series.items():
            if not dq: continue
            oks=[v[1] for v in dq]; lats=[v[2] for v in dq if not math.isnan(v[2])]
            cnt=len(dq); ok_rate=(sum(oks)/cnt)*100
            p50=percentile(lats,50) if lats else None
            p95=percentile(lats,95) if lats else None
            last_latency=next((v[2] for v in reversed(dq) if not math.isnan(v[2])),math.nan)
            age=(now-last_ts.get(k,now)).total_seconds()
            rows.append(dict(key=k,count=cnt,ok_rate=ok_rate,p50=p50,p95=p95,last=last_latency,age=age))
        rows.sort(key=lambda r:(r["ok_rate"],-(r["p95"] if r["p95"] is not None else -1)))
        return rows

    while True:
        roll_if_new_day()
        file_pos,lines = tail_csv(csv_path,file_pos)
        if lines: ingest(lines)

        clear_console()
        print("DNSHealthViz (console w/ thresholds) | Source:", csv_path)
        print("Window:", args.window, "points  Refresh:", args.refresh,"s  UTC:", dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        print("-"*110)
        hdr="{:<34} {:>5} {:>9} {:>10} {:>10} {:>9} {:>7}".format(
            "Series", "N","OK%","p50","p95","Last","Age")
        print(hdr); print("-"*110)

        rows=summarize()
        if not rows: print("(waiting for data…)")
        else:
            for r in rows:
                key_str=r["key"] if isinstance(r["key"],str) else f"{r['key'][0]} / {r['key'][1]}"
                okpct=f"{r['ok_rate']:.1f}"
                p95s=fmt_ms(r["p95"])
                p50s=fmt_ms(r["p50"])
                lasts=fmt_ms(r["last"])
                age=f"{int(r['age']):>3}s"

                # threshold checks
                if r["ok_rate"] < THRESH_OK:
                    okpct=red(okpct)
                elif r["ok_rate"]<99.9:
                    okpct=yellow(okpct)
                else:
                    okpct=green(okpct)

                if r["p95"] is not None and r["p95"]>THRESH_P95:
                    p95s=red(p95s)

                line="{:<34} {:>5} {:>9} {:>10} {:>10} {:>9} {:>7}".format(
                    key_str[:34],r["count"],okpct,p50s,p95s,lasts,age)
                print(line)

        print("-"*110)
        print(f"Legend: OK%< {THRESH_OK} → RED | p95 > {THRESH_P95}ms → RED")
        time.sleep(args.refresh)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: pass
