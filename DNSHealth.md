# Raw scatter, per resolver (default), color failures, add 10ms threshold, limit y to 200ms
python3 DNSHealthGraph_raw.py \
  --csv-dir ~/DNS \
  --threshold-ms 10 --y-max 200 \
  --out ~/DNS/dns_raw_resolvers.png

# Raw scatter, per target (resolver/target facets), with slight jitter to separate overlaps
python3 DNSHealthGraph_raw.py \
  --csv-dir ~/DNS \
  --group-by-target --jitter 0.3 --y-max 200 --threshold-ms 10 \
  --out ~/DNS/dns_raw_targets.png

# Focus on specific resolver and target(s)
python3 DNSHealthGraph_raw.py \
  --csv-dir ~/DNS \
  --resolver 167.190.40.21 \
  --target Host --target host \
  --y-max 300 --threshold-ms 10 \
  --out ~/DNS/dns_focus.png
