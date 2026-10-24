import streamlit as st
import pandas as pd

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield",
    page_icon="🛡️",
    layout="wide",
)

# ── Dark-theme styling ────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
        /* Main background */
        .stApp { background-color: #0d1117; color: #e6edf3; }

        /* Metric cards */
        [data-testid="metric-container"] {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px 24px;
        }

        /* Metric label */
        [data-testid="metric-container"] label {
            color: #8b949e !important;
            font-size: 13px !important;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Metric value */
        [data-testid="metric-container"] [data-testid="stMetricValue"] {
            color: #58a6ff !important;
            font-size: 2.4rem !important;
            font-weight: 700;
        }

        /* Hide Streamlit branding */
        #MainMenu, footer { visibility: hidden; }

        /* Divider colour */
        hr { border-color: #30363d; }

        /* Table header */
        thead tr th {
            background-color: #161b22 !important;
            color: #8b949e !important;
            font-size: 12px !important;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Table rows */
        tbody tr td { font-size: 14px !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── 20 fake login records ─────────────────────────────────────────────────────
# Several failed attempts from 192.168.4.77 simulate a brute-force attack.
SAMPLE_RECORDS = [
    {"Time": "2024-06-10 08:01:32", "Username": "alice",   "IP Address": "192.168.1.10",  "Result": "Success"},
    {"Time": "2024-06-10 08:03:14", "Username": "bob",     "IP Address": "192.168.1.22",  "Result": "Success"},
    {"Time": "2024-06-10 08:07:45", "Username": "carol",   "IP Address": "10.0.0.5",      "Result": "Success"},
    {"Time": "2024-06-10 08:12:09", "Username": "admin",   "IP Address": "192.168.4.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:12:41", "Username": "admin",   "IP Address": "192.168.4.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:13:05", "Username": "admin",   "IP Address": "192.168.4.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:13:29", "Username": "root",    "IP Address": "192.168.4.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:13:52", "Username": "root",    "IP Address": "192.168.4.77",  "Result": "Failed"},
    {"Time": "2024-06-10 08:15:00", "Username": "david",   "IP Address": "10.0.0.18",     "Result": "Success"},
    {"Time": "2024-06-10 08:22:33", "Username": "eve",     "IP Address": "172.16.0.3",    "Result": "Success"},
    {"Time": "2024-06-10 08:31:17", "Username": "frank",   "IP Address": "192.168.1.55",  "Result": "Failed"},
    {"Time": "2024-06-10 08:45:02", "Username": "grace",   "IP Address": "10.0.0.42",     "Result": "Success"},
    {"Time": "2024-06-10 09:00:11", "Username": "henry",   "IP Address": "192.168.1.10",  "Result": "Success"},
    {"Time": "2024-06-10 09:14:38", "Username": "iris",    "IP Address": "172.16.0.9",    "Result": "Success"},
    {"Time": "2024-06-10 09:27:55", "Username": "jack",    "IP Address": "10.0.0.5",      "Result": "Failed"},
    {"Time": "2024-06-10 09:33:44", "Username": "karen",   "IP Address": "192.168.2.88",  "Result": "Success"},
    {"Time": "2024-06-10 09:41:20", "Username": "leo",     "IP Address": "192.168.1.22",  "Result": "Success"},
    {"Time": "2024-06-10 09:52:07", "Username": "maria",   "IP Address": "10.0.0.18",     "Result": "Success"},
    {"Time": "2024-06-10 10:05:49", "Username": "nick",    "IP Address": "172.16.0.3",    "Result": "Success"},
    {"Time": "2024-06-10 10:18:23", "Username": "olivia",  "IP Address": "192.168.2.101", "Result": "Success"},
]

# ── Session state — records start empty until the button is clicked ───────────
if "records" not in st.session_state:
    st.session_state.records = []

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ CyberShield Security Dashboard")
st.markdown(
    "Real-time overview of authentication activity and threat detection "
    "across all monitored systems."
)
st.divider()

# ── Suspicion rule ────────────────────────────────────────────────────────────
# RULE: if the same IP address has 5 or more failed login attempts, it is
#       considered suspicious (possible brute-force attack).
SUSPICIOUS_THRESHOLD = 5

def find_suspicious_ips(records):
    """
    Go through every record and count failed attempts per IP address.
    Return a dict like: { "192.168.4.77": 5 }  for every IP that hit
    the threshold.
    """
    # Step 1 – count failures per IP using a plain dictionary
    failed_counts = {}  # key = IP address, value = number of failed logins

    for record in records:
        if record["Result"] == "Failed":          # only count failures
            ip = record["IP Address"]
            if ip in failed_counts:
                failed_counts[ip] += 1            # already seen this IP → add 1
            else:
                failed_counts[ip] = 1             # first failure from this IP

    # Step 2 – keep only IPs that reached the threshold
    suspicious = {}
    for ip, count in failed_counts.items():
        if count >= SUSPICIOUS_THRESHOLD:         # ← the rule lives here
            suspicious[ip] = count

    return suspicious                             # e.g. {"192.168.4.77": 5}


# ── Build DataFrame and run the rule ─────────────────────────────────────────
df = pd.DataFrame(st.session_state.records)
suspicious_ips = find_suspicious_ips(st.session_state.records)

if df.empty:
    total_logins = successful_logins = failed_logins = suspicious_activities = 0
else:
    total_logins          = len(df)
    successful_logins     = len(df[df["Result"] == "Success"])
    failed_logins         = len(df[df["Result"] == "Failed"])
    suspicious_activities = len(suspicious_ips)   # one count per flagged IP

# ── Metric cards ──────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
col1.metric("🔐 Total Logins",          total_logins)
col2.metric("✅ Successful Logins",     successful_logins)
col3.metric("❌ Failed Logins",         failed_logins)
col4.metric("⚠️ Suspicious Activities", suspicious_activities)

st.divider()

# ── Generate Sample Data button ───────────────────────────────────────────────
if st.button("⚡ Generate Sample Data", type="primary"):
    st.session_state.records = SAMPLE_RECORDS
    st.rerun()

# ── Charts (only shown when records exist) ────────────────────────────────────
if not df.empty:
    st.subheader("📊 Login Overview Charts")
    chart_col1, chart_col2 = st.columns(2)

    # ── Chart 1: Successful vs Failed logins ─────────────────────────────────
    # This bar chart gives an instant visual of the login health.
    # A large "Failed" bar compared to "Success" is an early warning sign.
    with chart_col1:
        st.markdown("**Login Results — Success vs Failed**")
        st.caption("Compare how many logins succeeded against how many failed.")

        # Count how many records have each result value
        result_counts = df["Result"].value_counts()          # pandas Series
        result_df = pd.DataFrame({
            "Result": result_counts.index.tolist(),          # ["Success", "Failed"]
            "Count":  result_counts.values.tolist(),         # [14, 6]
        })
        st.bar_chart(result_df.set_index("Result"))

    # ── Chart 2: Failed logins by IP address ─────────────────────────────────
    # This chart reveals which IP addresses are generating the most failures.
    # A single IP with many failures stands out immediately as suspicious.
    with chart_col2:
        st.markdown("**Failed Login Attempts by IP Address**")
        st.caption("Each bar is one IP. Tall bars mean many failures from that source.")

        # Filter to only failed rows, then count failures per IP
        failed_df = df[df["Result"] == "Failed"]             # keep only failures
        failures_by_ip = failed_df["IP Address"].value_counts()
        ip_df = pd.DataFrame({
            "IP Address": failures_by_ip.index.tolist(),
            "Failed Attempts": failures_by_ip.values.tolist(),
        })
        st.bar_chart(ip_df.set_index("IP Address"))

st.divider()

# ── Filters sidebar ───────────────────────────────────────────────────────────
st.sidebar.header("🔍 Filters")

# Filter 1 – Risk level
# "High Risk" = IPs flagged as suspicious; "All" = show every alert
risk_options = ["All", "High Risk Only"]
selected_risk = st.sidebar.selectbox(
    "Alert Risk Level",
    options=risk_options,
    help="High Risk = IP has 5+ failed attempts (brute-force threshold).",
)

# Filter 2 – Login result
# Lets the analyst focus on just failures or just successes in the records table
result_options = ["All", "Success", "Failed"]
selected_result = st.sidebar.selectbox(
    "Login Result",
    options=result_options,
    help="Filter the Login Records table by outcome.",
)

# ── Suspicious IP warnings (respect the risk filter) ─────────────────────────
if suspicious_ips:
    st.subheader("🚨 Suspicious Activity Detected")

    for ip, count in suspicious_ips.items():
        # Determine the risk label for this IP
        if count >= SUSPICIOUS_THRESHOLD:
            risk_label = "High Risk"
        else:
            risk_label = "Low Risk"

        # Only show the warning if the filter matches
        if selected_risk == "All" or selected_risk == "High Risk Only":
            st.warning(
                f"**[{risk_label}]** &nbsp; IP Address **{ip}** — "
                f"**{count} failed login attempts** detected. "
                f"Exceeds the threshold of {SUSPICIOUS_THRESHOLD}. "
                f"Possible brute-force attack — investigate immediately."
            )
elif not df.empty:
    # Records exist but no IPs hit the threshold
    if selected_risk == "High Risk Only":
        st.info("No high-risk IPs found in the current records.")

# ── Login records table (respect the result filter) ──────────────────────────
st.subheader("📋 Login Records")

if df.empty:
    st.info("No records yet. Click **Generate Sample Data** to load 20 example login events.")
else:
    # Apply the result filter: keep all rows or only the selected result
    if selected_result == "All":
        filtered_df = df                                    # no filtering needed
    else:
        filtered_df = df[df["Result"] == selected_result]  # e.g. only "Failed"

    st.caption(f"Showing **{len(filtered_df)}** of **{len(df)}** records  •  Filter: {selected_result}")

    # Colour-code the Result column
    def highlight_result(val):
        if val == "Success":
            return "color: #3fb950; font-weight: 600;"   # green
        elif val == "Failed":
            return "color: #f85149; font-weight: 600;"   # red
        return ""

    styled = filtered_df.style.map(highlight_result, subset=["Result"])
    st.dataframe(styled, use_container_width=True, hide_index=True)

st.divider()
st.caption("CyberShield v1.0  •  All times in UTC")
