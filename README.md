# Port Health Monitoring Suite

A lightweight toolkit for monitoring TCP port health across internal infrastructure.  
Designed for locked-down environments — minimal dependencies, CSV-based logging, and matplotlib for reporting.

---

## 📦 Components

### 1. Collector — `portHealthChk.py`
- Continuously TCP-connects to endpoints and logs results.
- **Output CSV:** `sr_trend_<YYYY-MM-DD>_<port>.csv` (UTC date + port).
- Logs: `timestamp_utc, endpoint, port, success, latency_ms, error, src_ip, dst_ip`.
- **Dependencies:** Python stdlib only.

---

### 2. Console Dashboard — `portHealthViz.py`
- Live text dashboard in terminal.
- Discovers CSVs automatically, prompts if multiple exist.
- Rolling OK%, p50, p95, mean, last, age per endpoint/route.
- Color-coded thresholds for executive readability.
- **Dependencies:** Python stdlib only.

---

### 3. Executive Report — `portHealthExecReport.py`
- Generates **PNG** for leadership review.
- Auto-discovers CSV, infers port from filename.
- **Output PNG:**  
  `exec_<port-or-all>_<YYYY-MM-DD>_<HHMMZ>Z.png`
- Shows:
  - KPIs (Total connects, OK%, fails, p50, p95)
  - p95 trend lines (overall, endpoint, or route)
  - Top offenders bar chart
- **Dependencies:** matplotlib.

---

### 4. Scatter Report — `portHealthScatter.py`
- Raw scatter plot of connect latencies (OK vs Fail).
- Useful for spotting spikes hidden by averages.
- **Output PNG:**  
  `scatter_<port-or-all>_<YYYY-MM-DD>_<HHMMZ>Z.png`
- Options: jitter, dot size, y-axis clamp, threshold lines.
- **Dependencies:** matplotlib.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r portHealthrequirements.txt
