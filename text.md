Citrix docs don’t specify “N ms,” but they do say VDAs must have fast, reliable name resolution. In practice:

Anything that adds >10 ms DNS lookup time per transaction starts to impact VDA registration and ICA launch.

What usually kills stability is not average latency but tail latency (p95/p99) and timeouts. A few 50–100 ms outliers during DDC SRV record lookups can make the VDA unregister.
