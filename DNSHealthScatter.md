# Basic: facet per resolver, 10ms threshold, clip to 200ms
python3 DNSHealthScatter.py \
  --csv-dir ~/DNS/logs --date $(date -u +%F) \
  --group-by resolver --threshold-ms 10 --y-max 200 \
  --out ~/DNS/dns_scatter_resolvers.png

# Per route (src→dst), slight jitter to reveal overlaps
python3 DNSHealthScatter.py \
  --csv-dir ~/DNS/logs --group-by route --jitter 0.3 \
  --y-max 200 --threshold-ms 10 \
  --out ~/DNS/dns_scatter_routes.png

# Focus on a specific resolver and a couple of targets
python3 DNSHealthScatter.py \
  --csv-dir ~/DNS/logs --group-by target \
  --resolver IPADDRESS \
  --target ddc01.corp.local(A) --target _ldap._tcp.corp.local(SRV) \
  --y-max 300 --threshold-ms 10 \
  --out ~/DNS/dns_scatter_targets.png

# Direct CSV path
python3 DNSHealthScatter.py \
  --csv ~/DNS/logs/dns_trend_$(date -u +%F).csv \
  --group-by route --out ~/DNS/dns_scatter.png

