"""
VaultGuard — Secrets Management Dashboard
S2-P-08 · Cowshik Eswaramoorthy (P466)
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import json
import os
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────
# Page config — wide, no sidebar by default
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="VaultGuard \u2014 Secrets Management Dashboard",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ──────────────────────────────────────────────
# Custom CSS — compact, edge-to-edge, professional
# ──────────────────────────────────────────────
st.markdown("""
<style>
    .block-container {
        padding: 1rem 2rem 1rem 2rem !important;
        max-width: 100% !important;
    }
    [data-testid="stMetric"] {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 10px 14px;
    }
    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        font-size: 1.6rem;
        font-weight: 700;
        color: #0f172a;
    }
    [data-testid="stMetric"] [data-testid="stMetricLabel"] {
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: #64748b;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 0;
        background: #f1f5f9;
        border-radius: 8px;
        padding: 3px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.82rem;
        padding: 7px 18px;
    }
    .stTabs [aria-selected="true"] {
        background: #fff;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    h1 { font-size: 1.4rem !important; font-weight: 800 !important; margin-bottom: 0.3rem !important; }
    h2 { font-size: 1.05rem !important; font-weight: 700 !important; margin-top: 0.3rem !important; margin-bottom: 0.1rem !important; }
    h3 { font-size: 0.9rem !important; font-weight: 600 !important; }
    .streamlit-expanderHeader { font-weight: 600; font-size: 0.88rem; }
    div[data-testid="stExpander"] { border: 1px solid #e2e8f0; border-radius: 8px; }
    .footer-text {
        text-align: center;
        font-size: 0.68rem;
        color: #94a3b8;
        padding: 0.8rem 0 0.3rem 0;
        border-top: 1px solid #e2e8f0;
        margin-top: 1.5rem;
    }
    .guidance-section {
        background: #f8fafc;
        border-left: 3px solid #1e40af;
        padding: 12px 16px;
        margin-bottom: 12px;
        border-radius: 0 6px 6px 0;
        font-size: 0.88rem;
        line-height: 1.55;
        color: #334155;
    }
    .guidance-section strong { color: #0f172a; }
    .filter-bar {
        background: #f1f5f9;
        border-radius: 8px;
        padding: 8px 12px;
        margin-bottom: 10px;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# Colors
# ──────────────────────────────────────────────
IDENTITY_COLORS = {
    "github-actions-cicd": "#1e40af",
    "dev-user-alice": "#0891b2",
    "admin-bob": "#7c3aed",
}
STATUS_COLORS = {"200": "#059669", "403": "#dc2626"}
ANOMALY_COLORS = ["#d97706", "#dc2626", "#7c3aed"]

CHART_LAYOUT = dict(
    font=dict(family="Inter, system-ui, sans-serif", size=11, color="#334155"),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    margin=dict(l=35, r=15, t=25, b=35),
    xaxis=dict(gridcolor="#e2e8f0", zerolinecolor="#e2e8f0"),
    yaxis=dict(gridcolor="#e2e8f0", zerolinecolor="#e2e8f0"),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, font=dict(size=10)),
    hoverlabel=dict(bgcolor="#1e293b", font_color="#f8fafc", font_size=11),
)


def style(fig, h=280):
    fig.update_layout(**CHART_LAYOUT, height=h)
    return fig


# ──────────────────────────────────────────────
# Load data
# ──────────────────────────────────────────────
D = "data"


def load(path):
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


audit_logs = load(os.path.join(D, "synthetic", "vault-audit-logs.json")) or []
anomaly_report = load(os.path.join(D, "anomaly-report.json")) or {}
rotation_log = load(os.path.join(D, "rotation-log.json")) or []
rotation_policies = load(os.path.join(D, "rotation-policies.json")) or {}
audit_docs = load(os.path.join(D, "audit-documentation.json")) or {}

if audit_logs:
    df = pd.DataFrame([{
        "timestamp": e["time"],
        "identity": e["auth"]["display_name"],
        "path": e["request"]["path"].replace("secret/data/", ""),
        "operation": e["request"]["operation"],
        "status": str(e["response"]["status_code"]),
        "is_anomaly": e.get("is_anomaly", False),
        "anomaly_type": e.get("anomaly_type"),
    } for e in audit_logs])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["date"] = df["timestamp"].dt.date
    df["hour"] = df["timestamp"].dt.hour
else:
    df = pd.DataFrame()

# ──────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────
hdr1, hdr2 = st.columns([3, 1])
with hdr1:
    st.markdown("# \U0001f6e1\ufe0f VaultGuard Dashboard")
with hdr2:
    st.markdown(
        '<div style="text-align:right; padding-top:6px;">'
        '<span style="font-size:0.72rem; color:#94a3b8;">S2-P-08 \u00b7 pSiddhi 2026-01 \u00b7 Cowshik Eswaramoorthy (P466)</span>'
        '</div>', unsafe_allow_html=True
    )

# ──────────────────────────────────────────────
# KPI row
# ──────────────────────────────────────────────
total_events = len(df) if not df.empty else 0
total_allowed = int((df["status"] == "200").sum()) if not df.empty else 0
total_denied = int((df["status"] == "403").sum()) if not df.empty else 0
total_anomalies = int(df["is_anomaly"].sum()) if not df.empty else 0
total_rotations = len(rotation_log)
total_policies = len(rotation_policies.get("policies", []))

k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Audit Events", f"{total_events:,}")
k2.metric("Allowed (200)", f"{total_allowed:,}")
k3.metric("Denied (403)", total_denied)
k4.metric("Anomalies", total_anomalies)
k5.metric("Rotations", total_rotations)
k6.metric("AI Policies", total_policies)

# ──────────────────────────────────────────────
# Tabs
# ──────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "\U0001f4ca  Access Patterns",
    "\U0001f504  Rotation & Policies",
    "\u26a0\ufe0f  Anomaly Feed",
    "\U0001f4cb  Compliance Docs",
    "\U0001f50d  Ask Audit AI",
    "\U0001f4d6  Guidance",
])

# ═════════════════════════════════════════════
# TAB 1 — ACCESS PATTERNS
# ═════════════════════════════════════════════
with tab1:
    if not df.empty:
        # Inline filter row
        f1, f2, f3 = st.columns(3)
        with f1:
            sel_identities = st.multiselect("Filter by Identity", df["identity"].unique().tolist(), default=df["identity"].unique().tolist(), key="t1_id")
        with f2:
            sel_paths = st.multiselect("Filter by Secret Path", df["path"].unique().tolist(), default=df["path"].unique().tolist(), key="t1_path")
        with f3:
            sel_status = st.multiselect("Filter by Status", df["status"].unique().tolist(), default=df["status"].unique().tolist(), key="t1_status")

        fdf = df[df["identity"].isin(sel_identities) & df["path"].isin(sel_paths) & df["status"].isin(sel_status)]

        # Row 1
        c1, c2, c3 = st.columns([1, 1, 1])
        with c1:
            st.markdown("## Requests by Identity")
            idc = fdf["identity"].value_counts().reset_index()
            idc.columns = ["Identity", "Count"]
            fig = px.bar(idc, x="Identity", y="Count", color="Identity", color_discrete_map=IDENTITY_COLORS, text="Count")
            fig.update_traces(textposition="outside", textfont_size=11)
            fig.update_xaxes(title=""); fig.update_yaxes(title="Requests")
            style(fig, 270); fig.update_layout(showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown("## Requests by Secret Path")
            pc = fdf["path"].value_counts().reset_index()
            pc.columns = ["Secret Path", "Count"]
            fig = px.bar(pc, x="Count", y="Secret Path", orientation="h", color="Count", color_continuous_scale=["#bfdbfe", "#1e40af"], text="Count")
            fig.update_traces(textposition="outside", textfont_size=11)
            fig.update_xaxes(title="Requests"); fig.update_yaxes(title="", categoryorder="total ascending")
            fig.update_coloraxes(showscale=False)
            style(fig, 270)
            st.plotly_chart(fig, use_container_width=True)

        with c3:
            st.markdown("## Response Status")
            sc = fdf["status"].value_counts().reset_index()
            sc.columns = ["Status", "Count"]
            fig = px.pie(sc, values="Count", names="Status", color="Status", color_discrete_map=STATUS_COLORS, hole=0.6)
            fig.update_traces(textinfo="percent+label", textfont_size=12)
            style(fig, 270)
            st.plotly_chart(fig, use_container_width=True)

        # Row 2
        c4, c5 = st.columns([2, 1])
        with c4:
            st.markdown("## Daily Access Trend")
            daily = fdf.groupby(["date", "identity"]).size().reset_index(name="Count")
            daily.columns = ["Date", "Identity", "Count"]
            fig = px.area(daily, x="Date", y="Count", color="Identity", color_discrete_map=IDENTITY_COLORS)
            fig.update_xaxes(title="Date"); fig.update_yaxes(title="Requests")
            style(fig, 260)
            st.plotly_chart(fig, use_container_width=True)

        with c5:
            st.markdown("## Operations")
            oc = fdf["operation"].value_counts().reset_index()
            oc.columns = ["Operation", "Count"]
            fig = px.pie(oc, values="Count", names="Operation", color_discrete_sequence=["#1e40af", "#0891b2"], hole=0.6)
            fig.update_traces(textinfo="percent+label", textfont_size=12)
            style(fig, 260)
            st.plotly_chart(fig, use_container_width=True)

        # Row 3
        c6, c7 = st.columns(2)
        with c6:
            st.markdown("## Hourly Activity (Stacked)")
            hourly = fdf.groupby(["hour", "identity"]).size().reset_index(name="Count")
            hourly.columns = ["Hour (UTC)", "Identity", "Count"]
            fig = px.bar(hourly, x="Hour (UTC)", y="Count", color="Identity", color_discrete_map=IDENTITY_COLORS, barmode="stack")
            fig.update_xaxes(title="Hour of Day (UTC)", dtick=2); fig.update_yaxes(title="Requests")
            style(fig, 260)
            st.plotly_chart(fig, use_container_width=True)

        with c7:
            st.markdown("## Identity x Secret Path Matrix")
            mx = fdf.groupby(["identity", "path"]).size().reset_index(name="Count")
            pv = mx.pivot_table(index="identity", columns="path", values="Count", fill_value=0)
            fig = px.imshow(pv, color_continuous_scale=["#f0f9ff", "#1e40af"], text_auto=True, aspect="auto",
                            labels=dict(x="Secret Path", y="Identity", color="Requests"))
            fig.update_xaxes(side="bottom", tickangle=25)
            style(fig, 260)
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No audit data found.")

# ═════════════════════════════════════════════
# TAB 2 — ROTATION & POLICIES
# ═════════════════════════════════════════════
with tab2:
    if rotation_log:
        rot_df = pd.DataFrame(rotation_log)
        rot_df["timestamp"] = pd.to_datetime(rot_df["timestamp"])
        success = int((rot_df["status"] == "success").sum())
        fail = int((rot_df["status"] != "success").sum())
        rate = round(success / len(rot_df) * 100, 1) if len(rot_df) > 0 else 0

        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Total Rotations", len(rot_df))
        r2.metric("Successful", success)
        r3.metric("Failed", fail)
        r4.metric("Success Rate", str(rate) + "%")

        rc1, rc2 = st.columns(2)
        with rc1:
            st.markdown("## Rotations per Secret Type")
            rtc = rot_df["secret_path"].value_counts().reset_index()
            rtc.columns = ["Secret Path", "Rotations"]
            fig = px.bar(rtc, x="Secret Path", y="Rotations", color="Rotations", color_continuous_scale=["#bbf7d0", "#059669"], text="Rotations")
            fig.update_traces(textposition="outside", textfont_size=11)
            fig.update_xaxes(title=""); fig.update_yaxes(title="Rotations")
            fig.update_coloraxes(showscale=False)
            style(fig, 280)
            st.plotly_chart(fig, use_container_width=True)

        with rc2:
            st.markdown("## Rotation Timeline")
            tl = rot_df.sort_values("timestamp")
            tl["type"] = tl["secret_path"].str.split("/").str[0]
            fig = px.scatter(tl, x="timestamp", y="type", color="status",
                             color_discrete_map={"success": "#059669", "failed": "#dc2626"},
                             labels={"timestamp": "Time", "type": "Secret Type", "status": "Status"})
            fig.update_traces(marker=dict(size=10))
            fig.update_xaxes(title="Timestamp"); fig.update_yaxes(title="")
            style(fig, 280)
            st.plotly_chart(fig, use_container_width=True)

        with st.expander("\U0001f4c4  Rotation Event Log"):
            show_df = rot_df[["timestamp", "secret_path", "old_version", "new_version", "status"]].copy()
            show_df.columns = ["Time", "Secret", "From", "To", "Status"]
            show_df = show_df.sort_values("Time", ascending=False)
            st.dataframe(show_df, use_container_width=True, hide_index=True, height=200)
    else:
        st.warning("No rotation data.")

    st.markdown("---")
    st.markdown("## AI-Generated Rotation Policies")
    st.caption("Gemini 2.5 Flash \u2014 structured rotation recommendation per secret category")

    policies = rotation_policies.get("policies", [])
    if policies:
        # Comparison chart
        pdf = pd.DataFrame([{
            "Category": p.get("category", "").replace("_", " ").title(),
            "Days": p.get("recommended_rotation_interval_days", 0),
        } for p in policies])
        fig = px.bar(pdf, x="Category", y="Days", color="Days", color_continuous_scale=["#fef3c7", "#d97706"], text="Days")
        fig.update_traces(textposition="outside", textfont_size=12)
        fig.update_xaxes(title=""); fig.update_yaxes(title="Recommended Interval (days)")
        fig.update_coloraxes(showscale=False)
        style(fig, 250)
        st.plotly_chart(fig, use_container_width=True)

        for p in policies:
            cat = p.get("category", "").replace("_", " ").title()
            days = p.get("recommended_rotation_interval_days", "N/A")
            with st.expander("\U0001f4cb  " + cat + "  \u2014  " + str(days) + " day interval"):
                lc, rc = st.columns(2)
                with lc:
                    st.markdown("**Strategy:** " + str(p.get("rotation_strategy", "\u2014")))
                    st.markdown("**Propagation:** " + str(p.get("propagation_method", "\u2014")))
                    st.markdown("**Blast Radius:** " + str(p.get("blast_radius_notes", "\u2014")))
                with rc:
                    st.markdown("**Justification:** " + str(p.get("justification", "\u2014")))
                    pre = p.get("pre_rotation_checks", [])
                    post = p.get("post_rotation_checks", [])
                    if pre:
                        st.markdown("**Pre-checks:** " + ", ".join(str(c) for c in pre))
                    if post:
                        st.markdown("**Post-checks:** " + ", ".join(str(c) for c in post))

# ═════════════════════════════════════════════
# TAB 3 — ANOMALY FEED
# ═════════════════════════════════════════════
with tab3:
    if anomaly_report and anomaly_report.get("anomalies_by_type"):
        abt = anomaly_report["anomalies_by_type"]
        tc = {k: len(v) for k, v in abt.items()}

        a1, a2, a3, a4 = st.columns(4)
        a1.metric("Total Anomalies", sum(tc.values()))
        a2.metric("Off-Hours", tc.get("off_hours_access", 0))
        a3.metric("Unusual Pairing", tc.get("unusual_identity_secret_pairing", 0))
        a4.metric("Frequency Burst", tc.get("abnormal_access_frequency", 0))

        ac1, ac2 = st.columns(2)
        with ac1:
            st.markdown("## Anomaly Distribution")
            adf = pd.DataFrame([{"Type": k.replace("_", " ").title(), "Count": v} for k, v in tc.items()])
            fig = px.bar(adf, x="Type", y="Count", color="Type", color_discrete_sequence=ANOMALY_COLORS, text="Count")
            fig.update_traces(textposition="outside", textfont_size=12)
            fig.update_xaxes(title=""); fig.update_yaxes(title="Events")
            style(fig, 280); fig.update_layout(showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

        with ac2:
            st.markdown("## Severity Breakdown")
            high = tc.get("abnormal_access_frequency", 0)
            medium = tc.get("off_hours_access", 0) + tc.get("unusual_identity_secret_pairing", 0)
            sdf = pd.DataFrame([{"Severity": "High", "Count": high}, {"Severity": "Medium", "Count": medium}])
            fig = px.pie(sdf, values="Count", names="Severity", color="Severity",
                         color_discrete_map={"High": "#dc2626", "Medium": "#d97706"}, hole=0.6)
            fig.update_traces(textinfo="percent+label", textfont_size=13)
            style(fig, 280)
            st.plotly_chart(fig, use_container_width=True)

        # Timeline
        if not df.empty:
            anomaly_entries = df[df["is_anomaly"]].copy()
            if not anomaly_entries.empty:
                st.markdown("## Anomaly Timeline")
                anomaly_entries["Type"] = anomaly_entries["anomaly_type"].fillna("unknown").str.replace("_", " ").str.title()
                fig = px.scatter(anomaly_entries, x="timestamp", y="identity", color="Type",
                                 color_discrete_sequence=ANOMALY_COLORS, symbol="Type",
                                 hover_data=["path", "operation"],
                                 labels={"timestamp": "Timestamp", "identity": "Identity"})
                fig.update_traces(marker=dict(size=9))
                fig.update_xaxes(title="Time"); fig.update_yaxes(title="")
                style(fig, 230)
                st.plotly_chart(fig, use_container_width=True)

        # Events
        for atype, anomalies in abt.items():
            label = atype.replace("_", " ").title()
            sev = "\U0001f534 HIGH" if atype == "abnormal_access_frequency" else "\U0001f7e0 MEDIUM"
            with st.expander(sev + "  " + label + "  (" + str(len(anomalies)) + " events)"):
                for a in anomalies[:10]:
                    st.markdown("- " + a.get("detail", str(a)))

        st.markdown("---")
        st.markdown("## \U0001f916 AI Security Narration")
        st.caption("Groq \u2014 Llama 3.3 70B Versatile")
        narration = anomaly_report.get("ai_narration", "")
        if narration:
            st.markdown(narration)
    else:
        st.warning("No anomaly data found.")

# ═════════════════════════════════════════════
# TAB 4 — COMPLIANCE DOCS
# ═════════════════════════════════════════════
with tab4:
    if audit_docs:
        st.caption("AI-generated compliance documentation \u2014 Gemini 2.5 Flash")
        icons = {"access_policy_effectiveness": "\U0001f510", "rotation_compliance": "\U0001f504", "anomaly_response": "\u26a0\ufe0f"}
        for key, doc in audit_docs.items():
            title = doc.get("title", key)
            gen = doc.get("generated_at", "")[:10]
            content = doc.get("content", "")
            icon = icons.get(key, "\U0001f4cb")
            with st.expander(icon + "  " + title + "  (" + gen + ")"):
                st.markdown(content)
    else:
        st.warning("No audit documentation found.")

# ═════════════════════════════════════════════
# TAB 5 — ASK AUDIT AI (NL Query)
# ═════════════════════════════════════════════
with tab5:
    st.markdown("## Ask a Question About Your Audit Data")
    st.caption("Powered by Groq \u2014 Llama 3.3 70B \u00b7 Answers grounded in real Vault audit logs")

    # Build context once and cache in session state
    if "nl_context" not in st.session_state and audit_logs:
        from collections import Counter as NLCounter
        from collections import defaultdict as NLDefaultDict
        nl_by_identity = NLCounter()
        nl_by_path = NLCounter()
        nl_by_status = NLCounter()
        nl_by_hour = NLCounter()
        nl_identity_paths = NLDefaultDict(set)
        nl_denied = []
        nl_offhours = []
        for e in audit_logs:
            ident = e["auth"]["display_name"]
            path = e["request"]["path"]
            status = e["response"]["status_code"]
            ts = datetime.fromisoformat(e["time"])
            nl_by_identity[ident] += 1
            nl_by_path[path] += 1
            nl_by_status[status] += 1
            nl_by_hour[ts.hour] += 1
            nl_identity_paths[ident].add(path)
            if status == 403:
                nl_denied.append({"identity": ident, "path": path, "time": e["time"], "operation": e["request"]["operation"]})
            if ts.hour >= 22 or ts.hour < 6:
                nl_offhours.append({"identity": ident, "path": path, "time": e["time"], "hour": ts.hour})

        ctx = "VAULT AUDIT LOG DATA SUMMARY\n============================\n\n"
        ctx += "OVERVIEW:\n- Total events: " + str(len(audit_logs)) + "\n"
        ctx += "- Successful (200): " + str(nl_by_status.get(200, 0)) + "\n"
        ctx += "- Denied (403): " + str(nl_by_status.get(403, 0)) + "\n\n"
        ctx += "IDENTITIES:\n"
        for ident, count in nl_by_identity.most_common():
            ctx += "- " + ident + ": " + str(count) + " accesses to: " + ", ".join(sorted(nl_identity_paths[ident])) + "\n"
        ctx += "\nSECRET PATHS:\n"
        for path, count in nl_by_path.most_common():
            ctx += "- " + path + ": " + str(count) + " accesses\n"
        ctx += "\nACCESS BY HOUR:\n"
        for hour in sorted(nl_by_hour.keys()):
            ctx += "- " + str(hour).zfill(2) + ":00 \u2014 " + str(nl_by_hour[hour]) + " events\n"
        if nl_denied:
            ctx += "\nDENIED ACCESS (403):\n"
            for d in nl_denied[:15]:
                ctx += "- " + d["identity"] + " tried " + d["operation"] + " on " + d["path"] + " at " + d["time"] + "\n"
        if nl_offhours:
            ctx += "\nOFF-HOURS ACCESS:\n"
            for o in nl_offhours[:15]:
                ctx += "- " + o["identity"] + " accessed " + o["path"] + " at " + o["time"] + "\n"
        ctx += "\nPOLICIES:\n- developer: read on db-credentials, api-keys\n- cicd: read on db-credentials, api-keys, service-tokens, env-config\n- platform-admin: full CRUD on all paths\n"
        st.session_state["nl_context"] = ctx

    sample_questions = [
        "Who accessed secrets after hours?",
        "Were there any denied access attempts?",
        "Which secret was accessed most frequently?",
        "How many times did dev-user-alice access the system?",
        "Show me all activity by admin-bob",
    ]
    st.markdown("**Example questions:** " + " \u00b7 ".join(["*" + q + "*" for q in sample_questions[:3]]))

    user_question = st.text_input("Type your question:", placeholder="e.g. Who accessed secrets after hours?", key="nl_query_input")

    if st.button("Ask Audit AI", key="nl_query_btn", type="primary"):
        if user_question and "nl_context" in st.session_state:
            with st.spinner("Querying Groq..."):
                try:
                    from groq import Groq as GroqClient
                    client = GroqClient(api_key=os.getenv("GROQ_API_KEY"))
                    prompt = (
                        "You are a security analyst answering questions about Vault audit logs. "
                        "Answer using ONLY the data below. Be specific \u2014 cite identities, paths, timestamps, counts. "
                        "If data is insufficient, say so.\n\n"
                        + st.session_state["nl_context"] + "\n\n"
                        "QUESTION: " + user_question + "\n\nANSWER:"
                    )
                    resp = client.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.2,
                        max_tokens=1000
                    )
                    answer = resp.choices[0].message.content
                    st.markdown("### Answer")
                    st.markdown(answer)
                except Exception as ex:
                    st.error("Error querying Groq: " + str(ex))
        elif not user_question:
            st.warning("Please type a question first.")
        else:
            st.warning("No audit data available.")

# ═════════════════════════════════════════════
# TAB 6 — GUIDANCE
# ═════════════════════════════════════════════
with tab6:
    st.markdown("## What does this dashboard show?")
    st.markdown(
        '<div class="guidance-section">'
        '<strong>VaultGuard</strong> is a secrets management and rotation system. '
        'This dashboard visualises how secrets (passwords, API keys, certificates) are stored, '
        'who accesses them, when they are rotated, and whether anything unusual is happening. '
        'Every chart and number on this dashboard maps to a real security operations question.'
        '</div>', unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("## KPI Metrics (Top Row)")

    st.markdown(
        '<div class="guidance-section">'
        '<strong>Audit Events</strong> \u2014 The total number of times any identity (person or service) '
        'read, wrote, or listed a secret in Vault during the monitoring period. '
        'A high number is normal for active systems. What matters is the ratio of allowed vs denied.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Allowed (200)</strong> \u2014 Requests where Vault granted access because the identity '
        'had the correct policy permissions. This should be the vast majority of all events.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Denied (403)</strong> \u2014 Requests where Vault rejected access because the identity '
        'tried to read a secret outside their permitted scope. A small number of denials is healthy '
        '\u2014 it means policies are working. A sudden spike in denials could indicate misconfiguration or probing.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Anomalies</strong> \u2014 Events that our rule-based detection system flagged as unusual. '
        'Not every anomaly is a security incident \u2014 some are false positives. '
        'The Anomaly Feed tab shows what was flagged and the AI narration explains why.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Rotations</strong> \u2014 The number of times a secret was automatically replaced with a new value. '
        'Regular rotation limits how long a compromised credential remains valid. '
        'Each rotation generates a new version in Vault and logs the event.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>AI Policies</strong> \u2014 The number of secret categories for which Gemini has generated '
        'a structured rotation policy recommendation (interval, propagation method, blast radius notes).'
        '</div>', unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("## Access Patterns Tab")

    st.markdown(
        '<div class="guidance-section">'
        '<strong>Requests by Identity</strong> \u2014 Shows which user or service account is making the most '
        'secret access requests. In VaultGuard, there are three roles:<br>'
        '\u2022 <strong>github-actions-cicd</strong> \u2014 automated CI/CD pipeline (expected to be the most active)<br>'
        '\u2022 <strong>dev-user-alice</strong> \u2014 a developer with read-only access to dev secrets<br>'
        '\u2022 <strong>admin-bob</strong> \u2014 a platform admin with full access to all secrets'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Requests by Secret Path</strong> \u2014 Shows which secrets are accessed most often. '
        'Database credentials and API keys are typically the most frequently accessed because '
        'application services need them on every connection or API call.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Response Status</strong> \u2014 The split between allowed (200) and denied (403) requests. '
        'A healthy system shows 95%+ allowed. The denied requests come from developers '
        'or services attempting to access secrets outside their policy scope.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Daily Access Trend</strong> \u2014 How access volume changes day by day. '
        'Look for weekday vs weekend patterns (CI/CD runs on both, humans mostly on weekdays) '
        'and any sudden spikes that might indicate automated scanning or misconfigured jobs.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Hourly Activity</strong> \u2014 Shows what time of day secrets are being accessed. '
        'Business-hours activity (9am\u20136pm) from human users is normal. '
        'Off-hours activity from human accounts is flagged as an anomaly.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Identity x Secret Path Matrix</strong> \u2014 A heatmap showing exactly which identity '
        'accessed which secret and how many times. Dark blue cells indicate high access. '
        'Empty cells (zero) mean that identity never accessed that secret \u2014 which is expected '
        'when policies correctly restrict scope.'
        '</div>', unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("## Rotation & Policies Tab")

    st.markdown(
        '<div class="guidance-section">'
        '<strong>What is secret rotation?</strong> \u2014 Rotation means replacing a secret (password, key, token) '
        'with a new randomly generated value. The old value becomes invalid. '
        'This limits the damage window if a credential is compromised \u2014 even if an attacker stole a password, '
        'it stops working after the next rotation.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>Rotation Timeline</strong> \u2014 Shows when each rotation happened as dots on a timeline. '
        'Green dots mean the rotation succeeded. Red dots (if any) mean it failed \u2014 '
        'which triggers a rollback to the previous version and an alert.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>AI Rotation Policies</strong> \u2014 For each type of secret, Gemini analyses the category metadata '
        '(sensitivity level, number of consumers, usage pattern) and recommends:<br>'
        '\u2022 How often to rotate (interval in days)<br>'
        '\u2022 How to propagate the new value to all consumers<br>'
        '\u2022 What could go wrong if rotation fails midway (blast radius)<br>'
        '\u2022 What to check before and after rotating'
        '</div>', unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("## Anomaly Feed Tab")

    st.markdown(
        '<div class="guidance-section">'
        '<strong>What is an anomaly in VaultGuard?</strong> \u2014 An anomaly is a secret access event that '
        'deviates from normal patterns. Our system detects three types:'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>\U0001f7e0 Off-Hours Access</strong> \u2014 A human identity (not CI/CD) accessing secrets '
        'between 10pm and 6am. This is unusual because developers typically work during business hours. '
        'It could be legitimate (on-call engineer) or suspicious (compromised credentials being used while the real user is asleep).'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>\U0001f7e0 Unusual Identity-Secret Pairing</strong> \u2014 A developer accessing secrets they '
        'normally do not use. For example, a developer reading TLS certificates or service tokens '
        'when their policy only covers database credentials and API keys. '
        'Even if the request was denied (403), the attempt itself is worth investigating.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>\U0001f534 Abnormal Access Frequency</strong> \u2014 An identity making an unusually high number '
        'of requests in a short time window (more than 20 in 10 minutes). '
        'This is rated HIGH severity because it could indicate automated credential harvesting, '
        'a brute-force attack, or a misconfigured pipeline that is hammering Vault.'
        '</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="guidance-section">'
        '<strong>AI Security Narration</strong> \u2014 After rule-based detection flags anomalies, '
        'we send the flagged events to Groq (Llama 3.3 70B) which writes a plain-English security report. '
        'This report is designed for a compliance officer or security reviewer who needs to understand '
        'what happened without reading raw logs.'
        '</div>', unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("## Compliance Docs Tab")

    st.markdown(
        '<div class="guidance-section">'
        '<strong>What are these documents?</strong> \u2014 These are AI-generated compliance reports '
        'that summarise VaultGuard audit data into formats a compliance officer or auditor can review. '
        'Each document covers one theme:<br>'
        '\u2022 <strong>Access Policy Effectiveness</strong> \u2014 Are policies correctly restricting who can read what?<br>'
        '\u2022 <strong>Rotation Compliance</strong> \u2014 Are secrets being rotated on schedule?<br>'
        '\u2022 <strong>Anomaly Response</strong> \u2014 Are detected anomalies being addressed?<br><br>'
        'Each document includes an executive summary, findings, compliance status, and recommendations.'
        '</div>', unsafe_allow_html=True
    )

# ──────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────
st.markdown(
    '<div class="footer-text">'
    "VaultGuard \u00b7 IMPACT pSiddhi 3.0 \u00b7 S2-P-08 \u00b7 Cowshik Eswaramoorthy (P466) \u00b7 Platform Track \u00b7 Semester 2"
    "</div>",
    unsafe_allow_html=True,
)
