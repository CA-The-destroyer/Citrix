#!/usr/bin/env python3
# portHealthChk.py — Generic TCP health checker with CSV logging
#
# Features:
#   • Prompts for TCP port if omitted
#   • Writes CSV in the execution directory by default:
#       ./sr_trend_YYYY-MM-DD_<port>.csv (UTC date + port number)
#   • Optional: --csv "<path/to/file.csv>" to write to an explicit file (no daily rollover)
#
# Dependencies (stdlib only): argparse, csv, datetime, os, socket, time, json

import argparse, csv, datetime as dt, os, socket, time, json
from typing import List, Optional

DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT  = 2.0
DEFAULT_RETRIES  = 1
DEFAULT_PORT     = 2598

DEFAULT_TARGETS = [
    "storefront01.corp.local",
    "gateway-vip.corp.local",
    "vda01.corp.local",
]

def ensure_dir_for_file(path: str):
    d = os.path.dirname(path)
    if d and d not in (".", ""):
        os.makedirs(d, exist_ok=True)

def utc_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()

def dated_csv_path(port: int) -> str:
    d = dt.datetime.utcnow().strftime("%Y-%m-%d")
    return os.path.join(".", f"sr_trend_{d}_{port}.csv")

def write_header_if_needed(csv_path: str):
    ensure_dir_for_file(csv_path)
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp_utc","endpoint","port","success","latency_ms","error","src_ip","dst_ip"])

def append_row(csv_path: str, row: dict):
    ensure_dir_for_file(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            row["timestamp_utc"], row["endpoint"], row["port"], 1 if row["success"] else 0,
            row["latency_ms"], row["error"], row.get("src_ip",""), row.get("dst_ip","")
        ])

def parse_targets_file(path: Optional[str]):
    if not path:
        return list(DEFAULT_TARGETS)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for x in data:
        if isinstance(x, str) and x.strip():
            out.append(x.strip())
        elif isinstance(x, dict) and x.get("endpoint"):
            out.append(x["endpoint"].strip())
    return out

def resolve_ipv4(host: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                return sockaddr[0]
    except Exception:
        pass
    return None

def tcp_connect_once(dst_ip: str, port: int, timeout: float):
    s = None
    start = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((dst_ip, port))
        latency = (time.perf_counter() - start) * 1000.0
        src_ip = s.getsockname()[0]
        return True, round(latency, 2), src_ip, ""
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        src_ip = ""
        return False, round(latency, 2), src_ip, f"{type(e).__name__}: {e}"
    finally:
        try:
            if s: s.close()
        except Exception:
            pass

def check_endpoint(endpoint: str, port: int, timeout: float, retries: int):
    dst_ip = resolve_ipv4(endpoint) or endpoint
    tries = retries + 1
    last_err = ""
    lat = 0.0
    src_ip = ""
    for _ in range(tries):
        ok, lat, src_ip, err = tcp_connect_once(dst_ip, port, timeout)
        if ok:
            return {"success": True, "latency_ms": lat, "error": "", "src_ip": src_ip, "dst_ip": dst_ip}
        last_err = err
        time.sleep(0.05)
    return {"success": False, "latency_ms": lat, "error": last_err, "src_ip": src_ip, "dst_ip": dst_ip}

def prompt_port(default_port: int) -> int:
    try:
        inp = input(f"Port to test [default {default_port}]: ").strip()
        if not inp:
            return default_port
        p = int(inp)
        if 1 <= p <= 65535:
            return p
        else:
            print("Port must be 1–65535. Using default.")
            return default_port
    except Exception:
        print("Invalid input. Using default.")
        return default_port

def main():
    ap = argparse.ArgumentParser(description="TCP port health checker (CSV logger) — prompts for port if omitted")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    ap.add_argument("--port", type=int, help=f"TCP port to test (default {DEFAULT_PORT}); prompts if omitted")
    ap.add_argument("--targets", nargs="+", help="Space-separated hostnames/IPs (overrides defaults)")
    ap.add_argument("--targets-file", type=str, help='JSON list, e.g. ["host1","host2"] or [{"endpoint":"host"}]')
    ap.add_argument("--csv", type=str, help='Explicit CSV output path (overrides default naming)')
    args = ap.parse_args()

    port = args.port if args.port else prompt_port(DEFAULT_PORT)
    targets = args.targets if args.targets else parse_targets_file(args.targets_file)

    explicit_csv = args.csv
    current_day = dt.datetime.utcnow().strftime("%Y-%m-%d")

    print(f"[INFO] portHealthChk started | port={port} | targets={targets} | interval={args.interval}s timeout={args.timeout}s retries={args.retries}")
    while True:
        if explicit_csv:
            csv_path = explicit_csv
        else:
            today = dt.datetime.utcnow().strftime("%Y-%m-%d")
            if today != current_day:
                current_day = today
            csv_path = dated_csv_path(port)

        write_header_if_needed(csv_path)

        for ep in targets:
            res = check_endpoint(ep, port, args.timeout, args.retries)
            row = {
                "timestamp_utc": utc_iso(),
                "endpoint": ep,
                "port": port,
                "success": res["success"],
                "latency_ms": res["latency_ms"],
                "error": res["error"],
                "src_ip": res["src_ip"],
                "dst_ip": res["dst_ip"],
            }
            append_row(csv_path, row)
            time.sleep(0.03)

        time.sleep(args.interval)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Stopped.")
