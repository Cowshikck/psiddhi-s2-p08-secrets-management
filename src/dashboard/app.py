"""
VaultGuard - Streamlit Dashboard
Access patterns, rotation status, anomaly feed, audit summary.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import json
import os
import pandas as pd
from datetime import datetime
from collections import Counter, defaultdict

# Page config
st.set_page_config(
    page_title="VaultGuard Dashboard",
    page_icon="🔐",
    layout="wide"
)

# Data paths
DATA_DIR = "data"
AUDIT_LOG_PATH = os.path.join(DATA_DIR, "synthetic", "vault-audit-logs.json")
ANOMALY_REPORT_PATH = os.path.join(DATA_DIR, "anomaly-report.json")
ROTATION_LOG_PATH = os.path.join(DATA_DIR, "rotation-log.json")
POLICY_PATH = os.path.join(DATA_DIR, "rotation-policies.json")
AUDIT_DOCS_PATH = os.path.join(DATA_DIR, "audit-documentation.json")


def load_json(path):
    """Load JSON file safely."""
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


# --- Load all data ---
audit_logs = load_json(AUDIT_LOG_PATH) or []
anomaly_report = load_json(ANOMALY_REPORT_PATH) or {}
rotation_log = load_json(ROTATION_LOG_PATH) or []
rotation_policies = load_json(POLICY_PATH) or {}
audit_docs = load_json(AUDIT_DOCS_PATH) or {}

# --- Title ---
st.title("VaultGuard Dashboard")
st.caption("Secrets Management and Rotation System - S2-P-08")

# --- Top Metrics ---
col1, col2, col3, col4 = st.columns(4)

total_events = len(audit_logs)
total_anomalies = anomaly_report.get("total_anomalies_detected", 0)
total_rotations = len(rotation_log)
total_policies = len(rotation_policies.get("policies", []))

col1.metric("Audit Events", total_events)
col2.metric("Anomalies Detected", total_anomalies)
col3.metric("Rotations Completed", total_rotations)
col4.metric("AI Policies Generated", total_policies)

st.divider()

# --- Tabs ---
tab1, tab2, tab3, tab4 = st.tabs([
    "Access Patterns",
    "Rotation Status",
    "Anomaly Feed",
    "Audit Summary"
])

# ===== TAB 1: ACCESS PATTERNS =====
with tab1:
    st.header("Access Patterns")

    if audit_logs:
        df = pd.DataFrame([
            {
                "time": entry["time"],
                "identity": entry["auth"]["display_name"],
                "path": entry["request"]["path"].replace("secret/data/", ""),
                "operation": entry["request"]["operation"],
                "status": entry["response"]["status_code"],
                "is_anomaly": entry.get("is_anomaly", False)
            }
            for entry in audit_logs
        ])
        df["time"] = pd.to_datetime(df["time"])
        df["date"] = df["time"].dt.date
        df["hour"] = df["time"].dt.hour

        # Access by identity
        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("Access by Identity")
            identity_counts = df["identity"].value_counts().reset_index()
            identity_counts.columns = ["identity", "count"]
            fig1 = px.bar(identity_counts, x="identity", y="count", color="identity")
            fig1.update_layout(showlegend=False, height=350)
            st.plotly_chart(fig1, use_container_width=True)

        with col_b:
            st.subheader("Access by Secret Path")
            path_counts = df["path"].value_counts().reset_index()
            path_counts.columns = ["path", "count"]
            fig2 = px.pie(path_counts, values="count", names="path")
            fig2.update_layout(height=350)
            st.plotly_chart(fig2, use_container_width=True)

        # Access over time
        st.subheader("Access Over Time (by Date)")
        daily = df.groupby(["date", "identity"]).size().reset_index(name="count")
        fig3 = px.line(daily, x="date", y="count", color="identity")
        fig3.update_layout(height=350)
        st.plotly_chart(fig3, use_container_width=True)

        # Hourly heatmap
        st.subheader("Access by Hour of Day")
        hourly = df.groupby(["hour", "identity"]).size().reset_index(name="count")
        fig4 = px.bar(hourly, x="hour", y="count", color="identity", barmode="stack")
        fig4.update_layout(height=350, xaxis_title="Hour (UTC)", yaxis_title="Access Count")
        st.plotly_chart(fig4, use_container_width=True)

        # Status breakdown
        col_c, col_d = st.columns(2)
        with col_c:
            st.subheader("Response Status")
            status_counts = df["status"].value_counts().reset_index()
            status_counts.columns = ["status", "count"]
            status_counts["status"] = status_counts["status"].astype(str)
            fig5 = px.pie(status_counts, values="count", names="status",
                         color="status", color_discrete_map={"200": "green", "403": "red"})
            fig5.update_layout(height=300)
            st.plotly_chart(fig5, use_container_width=True)

        with col_d:
            st.subheader("Operations")
            op_counts = df["operation"].value_counts().reset_index()
            op_counts.columns = ["operation", "count"]
            fig6 = px.bar(op_counts, x="operation", y="count", color="operation")
            fig6.update_layout(showlegend=False, height=300)
            st.plotly_chart(fig6, use_container_width=True)
    else:
        st.warning("No audit log data found.")

# ===== TAB 2: ROTATION STATUS =====
with tab2:
    st.header("Rotation Status")

    if rotation_log:
        rot_df = pd.DataFrame(rotation_log)
        rot_df["timestamp"] = pd.to_datetime(rot_df["timestamp"])

        col_e, col_f = st.columns(2)

        with col_e:
            st.subheader("Rotation Events")
            st.dataframe(
                rot_df[["timestamp", "secret_path", "old_version", "new_version", "status"]],
                use_container_width=True,
                hide_index=True
            )

        with col_f:
            st.subheader("Rotations by Secret")
            rot_counts = rot_df["secret_path"].value_counts().reset_index()
            rot_counts.columns = ["secret_path", "count"]
            fig7 = px.bar(rot_counts, x="secret_path", y="count", color="secret_path")
            fig7.update_layout(showlegend=False, height=350)
            st.plotly_chart(fig7, use_container_width=True)

        # Rotation success rate
        success_count = len(rot_df[rot_df["status"] == "success"])
        fail_count = len(rot_df[rot_df["status"] != "success"])
        st.subheader("Rotation Success Rate")
        col_g, col_h, col_i = st.columns(3)
        col_g.metric("Successful", success_count)
        col_h.metric("Failed", fail_count)
        rate = round(success_count / len(rot_df) * 100, 1) if len(rot_df) > 0 else 0
        col_i.metric("Success Rate", str(rate) + "%")
    else:
        st.warning("No rotation log data found.")

    # AI Rotation Policies
    st.divider()
    st.subheader("AI-Generated Rotation Policies")
    policies = rotation_policies.get("policies", [])
    if policies:
        for policy in policies:
            category = policy.get("category", "Unknown")
            interval = policy.get("recommended_rotation_interval_days", "N/A")
            strategy = policy.get("rotation_strategy", "N/A")
            justification = policy.get("justification", "N/A")

            with st.expander(category + " - " + str(interval) + " days"):
                st.write("**Rotation Strategy:** " + str(strategy))
                st.write("**Propagation:** " + str(policy.get("propagation_method", "N/A")))
                st.write("**Blast Radius:** " + str(policy.get("blast_radius_notes", "N/A")))
                st.write("**Justification:** " + str(justification))

                pre_checks = policy.get("pre_rotation_checks", [])
                if pre_checks:
                    st.write("**Pre-rotation checks:**")
                    for check in pre_checks:
                        st.write("- " + str(check))

                post_checks = policy.get("post_rotation_checks", [])
                if post_checks:
                    st.write("**Post-rotation checks:**")
                    for check in post_checks:
                        st.write("- " + str(check))
    else:
        st.warning("No rotation policies found.")

# ===== TAB 3: ANOMALY FEED =====
with tab3:
    st.header("Anomaly Feed")

    if anomaly_report and anomaly_report.get("anomalies_by_type"):
        anomalies_by_type = anomaly_report["anomalies_by_type"]

        # Summary metrics
        type_counts = {k: len(v) for k, v in anomalies_by_type.items()}
        cols = st.columns(len(type_counts))
        for i, (atype, count) in enumerate(type_counts.items()):
            cols[i].metric(atype.replace("_", " ").title(), count)

        # Anomaly type distribution
        st.subheader("Anomaly Distribution")
        type_df = pd.DataFrame(list(type_counts.items()), columns=["type", "count"])
        fig8 = px.pie(type_df, values="count", names="type")
        fig8.update_layout(height=350)
        st.plotly_chart(fig8, use_container_width=True)

        # Detailed anomaly list
        st.subheader("Detected Anomalies")
        for atype, anomalies in anomalies_by_type.items():
            with st.expander(atype.replace("_", " ").title() + " (" + str(len(anomalies)) + " events)"):
                for a in anomalies[:10]:
                    st.write("- " + a.get("detail", str(a)))

        # AI Narration
        st.divider()
        st.subheader("AI Security Narration (Groq - Llama 3.3 70B)")
        narration = anomaly_report.get("ai_narration", "")
        if narration:
            st.markdown(narration)
        else:
            st.warning("No AI narration available.")
    else:
        st.warning("No anomaly data found.")

# ===== TAB 4: AUDIT SUMMARY =====
with tab4:
    st.header("Compliance Audit Documentation")

    if audit_docs:
        for theme_key, doc_data in audit_docs.items():
            title = doc_data.get("title", theme_key)
            generated = doc_data.get("generated_at", "unknown")
            content = doc_data.get("content", "No content available.")

            with st.expander(title + " (generated: " + generated[:10] + ")"):
                st.markdown(content)
    else:
        st.warning("No audit documentation found. Run audit_docs.py first.")

# --- Footer ---
st.divider()
st.caption("VaultGuard - IMPACT pSiddhi 3.0 - S2-P-08 - Cowshik Eswaramoorthy (P466)")