# Last 60 minutes, all resolvers, default thresholds (OK%≥95, p95≤10ms)
./DNSHealthExecReport.py --csv-dir ~/DNS/ --out ~/DNS/dns_exec.png

# Look at last 180 minutes and a specific resolver only
./DNSHealthExecReport.py --csv-dir ~/DNS --minutes 180  --resolver ##ips --out ~/DNS/dns_exec_3h.png

# Tighten p95 threshold to 8ms; show top 12 offenders
./DNSHealthExecReport.py --csv-dir ~/DNS --p95-thresh 8 --topn 12 --out ~/DNS/dns_exec_tight.png

