# Last 60 minutes, all resolvers, default thresholds (OK%≥95, p95≤10ms)
./DNSHealthExecReport.py --csv-dir ~/DNS/ --out ~/DNS/dns_exec.png

# Look at last 180 minutes and a specific resolver only
./DNSHealthExecReport.py --csv-dir ~/DNS --minutes 180  --resolver ##ips --out ~/DNS/dns_exec_3h.png

# Tighten p95 threshold to 8ms; show top 12 offenders
./DNSHealthExecReport.py --csv-dir ~/DNS --p95-thresh 8 --topn 12 --out ~/DNS/dns_exec_tight.png

# Overall (single line), 60 minutes
./DNSHealthExecReport.py --csv-dir ~/DNS/logs --out ~/DNS/dns_exec.png

# Per resolver trend lines (keeps top 8 series if many)
./DNSHealthExecReport.py --csv-dir ~/DNS/logs --trend-by resolver \
  --trend-max-series 6 --out ~/DNS/dns_exec_resolvers.png

# Per route (src→dst) trend lines
./DNSHealthExecReport.py --csv-dir ~/DNS/logs --trend-by route \
  --trend-max-series 8 --out ~/DNS/dns_exec_routes.png
