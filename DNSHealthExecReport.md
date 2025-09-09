# Last 60 minutes, all resolvers, default thresholds (OK%≥95, p95≤10ms)
python3 DNSHealthExecReport.py \
  --csv-dir ~/DNS/logs \
  --out ~/DNS/dns_exec.png

# Look at last 180 minutes and a specific resolver only
python3 DNSHealthExecReport.py \
  --csv-dir ~/DNS/logs \
  --minutes 180 \
  --resolver 167.190.40.21 \
  --out ~/DNS/dns_exec_3h.png

# Tighten p95 threshold to 8ms; show top 12 offenders
python3 DNSHealthExecReport.py \
  --csv-dir ~/DNS/logs \
  --p95-thresh 8 --topn 12 \
  --out ~/DNS/dns_exec_tight.png
