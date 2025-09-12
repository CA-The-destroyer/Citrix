Port Health Monitoring – Execution Guide
1. Collector (portHealthChk.py)

This script runs continuously and logs TCP connect health checks into a CSV in the current execution directory.

Run with default daily rollover:
python .\portHealthChk.py --port 443 --targets google.com


Output file:
.\sr_trend_YYYY-MM-DD.csv (rotates at UTC midnight).

Run with explicit CSV file (no rollover):
python .\portHealthChk.py --port 2598 --targets storefront01.corp.local --csv .\sr_trend_custom.csv


Output file:
.\sr_trend_custom.csv (all data in one file).

2. Console Dashboard (portHealthViz.py)

Interactive, rolling console dashboard.
Reads the same CSV the collector writes.

python .\portHealthViz.py --port-filter 443

Options:

--window 600 → show last 600 samples in memory

--group-by-route → aggregate by src->dst route

--show-mean → show mean latency alongside p50/p95

3. Executive PNG Report (portHealthExecReport.py)

Generates an executive summary PNG with KPIs, p95 trends, and offender bars.

python .\portHealthExecReport.py --port-filter 443


Input: .\sr_trend_YYYY-MM-DD.csv

Output (default): .\exec_443.png

If no --port-filter: .\exec_all.png

Options:

--minutes 120 → look at the last 2 hours

--trend-by route → show per-route p95 lines

--topn 5 → show top 5 worst offenders

--out .\custom_exec.png → custom output filename

4. Scatter PNG Report (portHealthScatter.py)

Generates a raw scatter plot of connect times (OK vs Fail).

python .\portHealthScatter.py --port-filter 443


Input: .\sr_trend_YYYY-MM-DD.csv

Output (default): .\scatter_443.png

If no --port-filter: .\scatter_all.png

Options:

--group-by route → facet by route

--y-max 300 → clamp Y axis at 300ms

--threshold-ms 80 → dashed horizontal line at 80ms

--out .\scatter_custom.png → custom output filename

5. Sanity Checks

List CSVs:

Get-ChildItem .\ | Where-Object Name -like 'sr_trend_*.csv'


Tail a live CSV:

Get-Content .\sr_trend_$(Get-Date -Format 'yyyy-MM-dd').csv -Wait

6. Python Requirements
Collector (portHealthChk.py)

Standard library only.

No external dependencies.

Dashboard (portHealthViz.py)

Standard library only.

No external dependencies.

Reports (Exec + Scatter)

Requires matplotlib.

requirements.txt
# For executive and scatter PNG reporting
matplotlib>=3.9.0


Install:

pip install -r requirements.txt


⚡ Workflow summary:

Start portHealthChk.py (collector).

Run portHealthViz.py for live console.

Run portHealthExecReport.py or portHealthScatter.py for PNG outputs.