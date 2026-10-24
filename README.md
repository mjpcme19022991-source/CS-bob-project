# 🛡️ CyberShield — Security Dashboard

A beginner-friendly cybersecurity monitoring dashboard built with **Python** and **Streamlit**. CyberShield displays login activity, detects suspicious behaviour using a simple rule, and visualises the data with charts and filters — all in a single file.

---

## 📸 Features

- **4 Metric Cards** — Total logins, successful logins, failed logins, and suspicious activities, all computed live from the data
- **Sample Data** — 20 fictional login records loaded with one button click, including a simulated brute-force attack pattern
- **Brute-Force Detection Rule** — Flags any IP address with 5 or more failed login attempts as suspicious
- **Warning Banners** — Clear alerts with the IP address, failure count, and risk level
- **2 Bar Charts** — Login results (Success vs Failed) and failed attempts by IP address
- **Sidebar Filters** — Filter alerts by risk level and filter the records table by login result
- **Dark Theme** — Clean, modern dark UI styled with custom CSS

---

## 🚀 Getting Started

### 1. Prerequisites

Make sure you have **Python 3.7+** installed.  
Check with:

```bash
python --version
```

### 2. Install Dependencies

```bash
pip install streamlit pandas
```

### 3. Run the App

```bash
streamlit run app.py
```

The app opens automatically in your browser at `http://localhost:8501`.

### 4. Load the Dashboard

Click the **⚡ Generate Sample Data** button to populate all cards, charts, and the records table.

---

## 📁 Project Structure

```
cyber/
├── app.py       ← entire application (single file, ~270 lines)
└── README.md    ← this file
```

### Sections inside `app.py`

| Section | Lines | Purpose |
|---|---|---|
| Page config & CSS | 1 – 61 | App settings and dark theme styling |
| Sample records | 63 – 86 | 20 fictional login events |
| Session state | 88 – 90 | Keep data alive between Streamlit reruns |
| Detection rule | 100 – 128 | `find_suspicious_ips()` function |
| Metrics & charts | 131 – 193 | Metric cards and two bar charts |
| Filters & table | 195 – 266 | Sidebar filters, alerts, records table |

---

## 🔍 How the Detection Rule Works

The brute-force detection rule is written with plain Python `for` loops and `if` statements — no machine learning, no external libraries.

```python
SUSPICIOUS_THRESHOLD = 5  # change this number to adjust sensitivity

def find_suspicious_ips(records):
    failed_counts = {}
    for record in records:
        if record["Result"] == "Failed":
            ip = record["IP Address"]
            if ip in failed_counts:
                failed_counts[ip] += 1
            else:
                failed_counts[ip] = 1
    suspicious = {}
    for ip, count in failed_counts.items():
        if count >= SUSPICIOUS_THRESHOLD:
            suspicious[ip] = count
    return suspicious
```

In the sample data, IP `192.168.4.77` makes **5 failed attempts** in under 2 minutes — triggering the alert.

---

## 📊 Charts

| Chart | What it shows | Security insight |
|---|---|---|
| **Login Results** | One bar for Success, one for Failed | A large Failed bar signals unusual login pressure |
| **Failures by IP** | One bar per IP, height = failure count | A single tall bar instantly identifies the attacker's IP |

---

## 🎛️ Filters

Both filters live in the **left sidebar**:

| Filter | Options | Effect |
|---|---|---|
| **Alert Risk Level** | All / High Risk Only | Shows or hides suspicious IP warning banners |
| **Login Result** | All / Success / Failed | Filters rows in the Login Records table |

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| Python 3 | Core language |
| Streamlit | Web framework — turns the script into a browser app |
| Pandas | Data filtering, counting, and grouping |
| Custom CSS | Dark theme and styled components |

---

## 💡 Sample Data Overview

| Metric | Value |
|---|---|
| Total records | 20 |
| Successful logins | 14 |
| Failed logins | 6 |
| Suspicious IPs | 1 (`192.168.4.77` — 5 failures) |

---

## 🔮 Possible Future Improvements

- Connect to a real login database or log file
- Add a time-series chart to show login volume over time
- Export filtered records to CSV
- Send email or SMS alerts when a suspicious IP is detected
- Add IP geolocation to show which country attacks originate from
- Add a login screen to protect the dashboard itself

---

## ⚠️ Disclaimer

All data in this project is **completely fictional** and used for educational purposes only. CyberShield does not connect to any real system, network, or database.

---

*CyberShield v1.0 — All times in UTC*
