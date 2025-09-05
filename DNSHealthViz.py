#!/usr/bin/env python3
# DNSHealthViz.py — live viewer for DNSHealthChk CSVs (matplotlib only, no pandas)
# Requires: matplotlib (install via your private /simple index)

import argparse, csv, datetime as dt, os, time, collections
from matplotlib import pyplot as plt
from matplotlib.animation import FuncAnimation

ROLLING_POINTS = 600      # keep last N points per series (e.g., 600 x 5s ≈ 50 min)
POLL_INTERVAL_MS = 2000   # refresh every 2 seconds
DATEFMT = "%Y-%m-%d"

def find_latest_csv(csv_dir: str) -> str:
    today = dt.datetime.utcnow().strftime(DATEFMT)
    return os.path.join(csv_dir, f"dns_trend_{today}.csv")

def tail_csv(path, start_pos=0):
    """Yield new rows from a CSV file starting at byte offset start_pos."""
    if not os.path.exists(path):
        return start_pos, []
    with open(path, "r", encoding="utf-8") as f:
        f.seek(start_pos)
        lines = f.readlines()
        new_pos = f.tell()
    rows = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        if start_pos == 0 and i == 0 and line.lower().startswith("timestamp_utc"):
            # header line
            continue
        rows.append(line)
    return new_pos, rows

def parse_row(line: str):
    # CSV columns:
    # timestamp_utc,resolver,query,type,success,latency_ms,rcode,answers,ttl,used_tcp,error
    r = next(csv.reader([line]))
    ts_iso, resolver, qname, rtype, success, latency_ms, rcode, answers, ttl, used_tcp, err = (r + [""]*11)[:11]
    # parse time
    try:
        ts = dt.datetime.fromisoformat(ts_iso.replace("Z","+00:00"))
    except Exception:
        ts = dt.datetime.utcnow()
    # parse latency
    try:
        lat = float(latency_ms)
    except Exception:
        lat = float("nan")
    ok = (rcode == "NOERROR") and (success in ("1", "True", "true"))
    return ts, resolver, qname, rtype, ok, lat

def main():
    ap = argparse.ArgumentParser(description="Live matplotlib viewer for DNSHealthChk CSVs")
    ap.add_argument("--csv-dir", required=True, help="Directory where DNSHealthChk writes CSVs (e.g., C:\\temp\\dns_trend)")
    ap.add_argument("--window", type=int, default=ROLLING_POINTS, help="Rolling points per series (default 600)")
    ap.add_argument("--group-by-target", action="store_true",
                    help="If set, one line per resolver+target. Default: aggregate per resolver.")
    ap.add_argument("--refresh-ms", type=int, default=POLL_INTERVAL_MS, help="UI refresh interval in ms (default 2000)")
    args = ap.parse_args()

    csv_path = find_latest_csv(args.csv_dir)
    file_pos = 0
    current_day = dt.datetime.utcnow().strftime(DATEFMT)

    # Data buffers
    series = {}       # key -> { "t": deque, "y": deque }
    ok_series = {}    # key -> { "t": deque, "y": deque } where y in {0,1}

    def key_of(resolver, qname, rtype):
        return (resolver, f"{qname} ({rtype})") if args.group_by_target else resolver

    # Matplotlib setup
    plt.figure("DNSHealthViz", figsize=(11, 6))
    ax_lat = plt.subplot2grid((3,1), (0,0), rowspan=2)
    ax_ok  = plt.subplot2grid((3,1), (2,0), rowspan=1, sharex=ax_lat)

    ax_lat.set_title("DNS Latency (ms)")
    ax_lat.set_ylabel("Latency (ms)")
    ax_ok.set_title("Success (1) / Failure (0)")
    ax_ok.set_ylim(-0.1, 1.1)
    ax_ok.set_xlabel("Time (UTC)")

    lines = {}     # key -> Line2D
    ok_lines = {}  # key -> Line2D

    def ensure_key(k):
        import collections as _c
        if k not in series:
            series[k] = {"t": _c.deque(maxlen=args.window),
                         "y": _c.deque(maxlen=args.window)}
        if k not in ok_series:
            ok_series[k] = {"t": _c.deque(maxlen=args.window),
                            "y": _c.deque(maxlen=args.window)}
        if k not in lines:
            (line,) = ax_lat.plot([], [], linewidth=1.8, label=str(k))
            lines[k] = line
            (oline,) = ax_ok.plot([], [], linewidth=1.2, label=str(k))
            ok_lines[k] = oline
            ax_lat.legend(loc="upper left", fontsize="small", ncols=2)

    def ingest_rows(rows):
        for line in rows:
            ts, resolver, qname, rtype, ok, lat = parse_row(line)
            k = key_of(resolver, qname, rtype)
            ensure_key(k)
            series[k]["t"].append(ts)
            series[k]["y"].append(lat)
            ok_series[k]["t"].append(ts)
            ok_series[k]["y"].append(1 if ok else 0)

    def maybe_roll_to_new_day():
        nonlocal csv_path, file_pos, current_day
        today = dt.datetime.utcnow().strftime(DATEFMT)
        if today != current_day:
            csv_path = find_latest_csv(args.csv_dir)
            file_pos = 0
            current_day = today

    def on_timer(_frame):
        nonlocal file_pos
        maybe_roll_to_new_day()
        file_pos, rows = tail_csv(csv_path, file_pos)
        if rows:
            ingest_rows(rows)

        # refresh lines
        for k, line in lines.items():
            t = series[k]["t"]; y = series[k]["y"]
            if len(t) > 0:
                line.set_data(t, y)
        for k, line in ok_lines.items():
            t = ok_series[k]["t"]; y = ok_series[k]["y"]
            if len(t) > 0:
                line.set_data(t, y)

        # autoscale
        if series:
            ax_lat.relim(); ax_lat.autoscale_view()
            ax_ok.relim();  ax_ok.autoscale_view(scalex=True, scaley=False)
        plt.tight_layout()

    anim = FuncAnimation(plt.gcf(), on_timer, interval=args.refresh_ms)
    print(f"[INFO] Live viewer watching: {csv_path}")
    print(f"[INFO] Ctrl+C to exit.")
    plt.show()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
