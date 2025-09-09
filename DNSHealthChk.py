#!/usr/bin/env python3
# DNSHealthChk.py — DNS health checker with CSV logging (+ src/dst capture)
# Requires: dnspython
# Notes:
#   - Appends two CSV columns: src_ip (local egress IP) and dst_ip (resolver IP)
#   - Defaults to internal resolver 167.190.40.21

import argparse
import csv
import datetime as dt
import json
import os
import socket
import time
from typing import List, Tuple, Optional
import ipaddress

import dns.resolver
import dns.exception
import dns.reversename
import dns.flags
import dns.rcode

# ----------------------------
# Defaults / Config
# ----------------------------
DEFAULT_INTERVAL = 30          # seconds between rounds
DEFAULT_TIMEOUT = 2.0          # per-query timeout seconds
DEFAULT_RETRIES = 1            # retries after initial attempt
DEFAULT_RESOLVERS = ["167.190.40.21"]  # your internal DNS only

CSV_DIR_DEFAULT = "C:\\temp\\dns_trend" if os.name == "nt" else "/var/log/dns_trend"

# Seed targets (use --targets-file to override)
DEFAULT_TARGETS = [
    {"name": "ddc01.yourdomain.local", "type": "A"},
    {"name": "ddc02.yourdomain.local", "type": "A"},
    {"name": "storefront.yourdomain.local", "type": "A"},
    {"name": "cloudconnector01.yourdomain.local", "type": "A"},
    {"name": "_ldap._tcp.yourdomain.local", "type": "SRV"},
    {"name": "_kerberos._tcp.yourdomain.local", "type": "SRV"},
    {"name": "gitlab.yourdomain.local", "type": "A"},
    {"name": "repo.yourdomain.local", "type": "A"},
]

# ----------------------------
# Utilities
# ----------------------------
def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def utc_iso():
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()

def today_csv_path(csv_dir: str) -> str:
    d = dt.datetime.utcnow().strftime("%Y-%m-%d")
    return os.path.join(csv_dir, f"dns_trend_{d}.csv")

def write_header_if_needed(csv_path: str):
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp_utc","resolver","query","type","success","latency_ms",
                "rcode","answers","ttl","used_tcp","error","src_ip","dst_ip"
            ])

def append_row(csv_path: str, row: dict):
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            row["timestamp_utc"], row["resolver"], row["query"], row["type"],
            1 if row["success"] else 0, row["latency_ms"], row["rcode"],
            row["answers"], row["ttl"], 1 if row["used_tcp"] else 0, row["error"],
            row.get("src_ip",""), row.get("dst_ip","")
        ])

def parse_targets_file(path: Optional[str]):
    if not path:
        return list(DEFAULT_TARGETS)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for it in data:
        name = it.get("name")
        rtype = (it.get("type") or "A").upper()
        if name:
            out.append({"name": name, "type": rtype})
    return out

def system_resolver(timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.timeout = timeout
    r.lifetime = timeout
    return r

def custom_resolver(ip: str, timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.timeout = timeout
    r.lifetime = timeout
    r.nameservers = [ip]
    return r

def get_resolvers(entries: List[str], timeout: float) -> List[Tuple[str, dns.resolver.Resolver]]:
    out = []
    for e in entries:
        if e.lower() == "system":
            out.append(("system", system_resolver(timeout)))
        else:
            try:
                ipaddress.ip_address(e)
            except ValueError:
                raise SystemExit(f"[ERROR] --resolvers entry '{e}' is not a valid IP (space-separated IPs, no commas or :53)")
            out.append((e, custom_resolver(e, timeout)))
    return out

def add_local_ptr_if_requested(targets: List[dict], want_ptr: bool, probe_host_for_ip: str = "167.190.40.21"):
    """
    If --probe-local-ptr is set, add the PTR of the machine's primary IPv4.
    We determine the local primary IP using a UDP "connect" to your internal resolver
    (no packets actually sent yet) — avoids referencing public IPs.
    """
    if not want_ptr:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((probe_host_for_ip, 53))
        ip = s.getsockname()[0]
        s.close()
        rev = dns.reversename.from_address(ip).to_text(omit_final_dot=True)
        targets.append({"name": rev, "type": "PTR"})
    except Exception:
        pass

def extract_answers(rrsets):
    if not rrsets:
        return ("", None)
    answers = []
    ttl = None
    for rrset in rrsets:
        ttl = getattr(rrset, "ttl", ttl)
        for rdata in rrset:
            answers.append(str(rdata))
    return (", ".join(answers), ttl)

def do_query(resolver: dns.resolver.Resolver, resolver_label: str,
             qname: str, qtype: str, timeout: float, retries: int) -> dict:
    start = time.perf_counter()
    used_tcp = False

    def finalize(success: bool, rcode: str, answers: str, ttl, err: str):
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "timestamp_utc": utc_iso(),
            "resolver": resolver_label,
            "query": qname,
            "type": qtype,
            "success": success,
            "latency_ms": round(latency, 2),
            "rcode": rcode,
            "answers": answers,
            "ttl": ttl,
            "used_tcp": used_tcp,
            "error": err
        }

    try:
        resp = resolver.resolve(qname, qtype, tcp=False, lifetime=timeout)
        ans, ttl = extract_answers(resp.response.answer)
        rc = dns.rcode.to_text(resp.response.rcode())
        if resp.response.flags & dns.flags.TC:
            resp = resolver.resolve(qname, qtype, tcp=True, lifetime=timeout)
            used_tcp = True
            ans, ttl = extract_answers(resp.response.answer)
            rc = dns.rcode.to_text(resp.response.rcode())
        return finalize(True, rc, ans, ttl, "")
    except dns.exception.Timeout:
        try:
            resp = resolver.resolve(qname, qtype, tcp=True, lifetime=timeout)
            used_tcp = True
            ans, ttl = extract_answers(resp.response.answer)
            rc = dns.rcode.to_text(resp.response.rcode())
            return finalize(True, rc, ans, ttl, "")
        except Exception as e2:
            if retries > 0:
                try:
                    resp = resolver.resolve(qname, qtype, tcp=False, lifetime=timeout)
                    ans, ttl = extract_answers(resp.response.answer)
                    rc = dns.rcode.to_text(resp.response.rcode())
                    return finalize(True, rc, ans, ttl, "")
                except Exception as e3:
                    return finalize(False, "TIMEOUT", "", None, f"{type(e3).__name__}: {e3}")
            return finalize(False, "TIMEOUT", "", None, "Timeout after UDP and TCP")
    except Exception as e:
        rc = "ERROR"
        try:
            if hasattr(e, "responses") and e.responses:
                rc = dns.rcode.to_text(e.responses[0].rcode())
        except Exception:
            pass
        return finalize(False, rc, "", None, f"{type(e).__name__}: {e}")

# -------- src/dst helpers --------
def pick_src_ip_for(resolver_ip: str) -> str:
    """Return the local source IPv4 that would be used to reach resolver_ip:53."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((resolver_ip, 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""

# ----------------------------
# Main loop
# ----------------------------
def main():
    ap = argparse.ArgumentParser(description="DNS health checker with CSV logging (dnspython)")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    ap.add_argument("--resolvers", nargs="+", default=DEFAULT_RESOLVERS,
                    help='Resolvers to test (e.g., 167.190.40.21 167.190.40.22). Use "system" to include local OS resolver.')
    ap.add_argument("--targets-file", type=str, help='JSON: [{"name":"fqdn","type":"A|AAAA|CNAME|SRV|PTR"}]')
    ap.add_argument("--probe-local-ptr", action="store_true",
                    help="Also probe PTR of this host’s primary IPv4 (discovered via UDP connect to internal DNS).")
    ap.add_argument("--csv-dir", type=str, default=CSV_DIR_DEFAULT)
    args = ap.parse_args()

    ensure_dir(args.csv_dir)
    targets = parse_targets_file(args.targets_file)
    # Probe IP uses first default resolver by default; override to first provided if present
    probe_ip = (args.resolvers[0] if args.resolvers else DEFAULT_RESOLVERS[0])
    add_local_ptr_if_requested(targets, args.probe_local_ptr, probe_host_for_ip=probe_ip)

    resolvers = get_resolvers(args.resolvers, args.timeout)

    # Map resolver label/IP -> source IP we’d use to reach it, and actual dst_ip
    src_ip_map = {}
    dst_ip_map = {}
    for label, r in resolvers:
        if label == "system":
            # choose first nameserver the system resolver will use (if present)
            dst = r.nameservers[0] if getattr(r, "nameservers", None) else ""
        else:
            dst = label
        dst_ip_map[label] = dst
        src_ip_map[label] = pick_src_ip_for(dst) if dst else ""

    print(f"[INFO] DNSHealthChk started | resolvers={[r[0] for r in resolvers]} | interval={args.interval}s timeout={args.timeout}s retries={args.retries}")
    print(f"[INFO] Targets: {', '.join([t['name']+'('+t['type']+')' for t in targets])}")

    while True:
        csv_path = today_csv_path(args.csv_dir)
        write_header_if_needed(csv_path)
        for t in targets:
            qname = t["name"]
            qtype = t.get("type", "A").upper()
            for label, r in resolvers:
                row = do_query(r, label, qname, qtype, args.timeout, args.retries)
                # decorate with src/dst fields
                row["src_ip"] = src_ip_map.get(label, "")
                row["dst_ip"] = dst_ip_map.get(label, "")
                append_row(csv_path, row)
                time.sleep(0.03)  # tiny spacing
        time.sleep(args.interval + (os.getpid() % 5) * 0.05)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Stopped.")
