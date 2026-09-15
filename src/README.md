import streamlit as st
import pandas as pd
import random
import json
import time
import plotly.express as px

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="D2 Threat Intel Correlation Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- MOCK LLM BLUF ENGINE ---
def generate_bluf_summary(alert_details):
    """
    Simulates a structured system prompt call to a large language model 
    (e.g., IBM Granite or OpenAI GPT-4o) parsing raw technical indicators into actionable BLUF formats.
    """
    # In production, replace with your active LLM API Client:
    # client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    # response = client.chat.completions.create(...)
    
    time.sleep(0.6) # Simulating API network latency
    technique = alert_details['mitre_technique']
    source = alert_details['source']
    score = alert_details['priority_score']
    
    bluf = f"""### ⚡ BOTTOM LINE UP FRONT (BLUF)
**CRITICAL THREAT DETECTED:** An active exploitation vector mapping to **MITRE {technique}** was correlated across **{source}** feeds. 

*   **Current Risk Profile:** Priority Score **{score:.1f}/100** (High Impact / Verified Indicators).
*   **Target Assessment:** Tactical asset cluster targets detected via multi-source sensor verification.
*   **Commander's Directive:** Immediate network isolation of affected hosts is **REQUIRED** within the hour. Deny external traffic from flagged egress routing paths.
"""
    return bluf

# --- SEED DATABASES & MOCK TELEMENTRY ---
@st.cache_data
def get_static_mitre_matrix():
    return {
        "Initial Access": ["T1190 - Exploit Facing App", "T1566 - Phishing", "T1133 - External Services"],
        "Execution": ["T1059 - Command & Scripting", "T1204 - User Execution", "T1053 - Scheduled Task"],
        "Persistence": ["T1098 - Account Manipulation", "T1547 - Boot/Logon Autostart", "T1078 - Valid Accounts"],
        "Exfiltration": ["T1020 - Automated Exfiltration", "T1041 - Exfiltration Over Channel", "T1048 - Exfiltration Alternative"]
    }

if 'alerts_df' not in st.session_state:
    # Generate 5 baseline structured feeds
    sources = ["SIEM Log", "Satellite Feed", "Cyber Sensor", "Intel Report"]
    techniques = ["T1566 - Phishing", "T1078 - Valid Accounts", "T1190 - Exploit Facing App", "T1059 - Command & Scripting", "T1020 - Automated Exfiltration"]
    tactics = ["Initial Access", "Persistence", "Initial Access", "Execution", "Exfiltration"]
    
    mock_data = []
    for i in range(12):
        conf = random.randint(40, 95)
        sev = random.randint(30, 100)
        crit = random.randint(1, 5)
        # Triage Scoring Formula: (Confidence * 0.4) + (Severity * 0.3) + (Asset Criticality * 20 * 0.3)
        p_score = (conf * 0.4) + (sev * 0.3) + ((crit * 20) * 0.3)
        idx = random.randint(0, len(techniques)-1)
        
        mock_data.append({
            "Alert ID": f"D2-2026-{1000+i}",
            "Timestamp": f"2026-09-15 07:{random.randint(10,19)}:42",
            "Source": random.choice(sources),
            "MITRE Tactic": tactics[idx],
            "MITRE Technique": techniques[idx],
            "Confidence": conf,
            "Severity": sev,
            "Asset Crit": crit,
            "Priority Score": round(p_score, 1),
            "Status": "Unassigned" if p_score < 75 else "Triaged"
        })
    st.session_state.alerts_df = pd.DataFrame(mock_data).sort_values(by="Priority Score", ascending=False).reset_index(drop=True)

# --- STREAMLIT DASHBOARD INTERFACE ---
st.title("🛡️ D2 Threat Intelligence Correlation & Prioritisation Platform")
st.caption("Command-Ready Real-Time Tactical Triage Engine — Context Enabled via watsonx.ai MCP Framework")

# Metrics Top Summary Bar
m1, m2, m3, m4 = st.columns(4)
high_priority_count = len(st.session_state.alerts_df[st.session_state.alerts_df["Priority Score"] >= 75])
m1.metric("Total Multi-Source Ingested", len(st.session_state.alerts_df), "+3 new feeds")
m2.metric("Critical Actions (Score ≥ 75)", high_priority_count, f"{high_priority_count} require BLUF")
m3.metric("False Positive Filter Efficiency", "94.2%", "+1.4% optimization")
m4.metric("Active MITRE Techniques", st.session_state.alerts_df["MITRE Technique"].nunique())

# Layout Separation Tabs
tab_dashboard, tab_mitre, tab_raw = st.tabs(["🎮 Operations Dashboard", "📊 MITRE ATT&CK Matrix", "⚙️ Raw Live Stream Ingestion"])

with tab_dashboard:
    col_left, col_right = st.columns([3, 2])
    
    with col_left:
        st.subheader("🔥 Prioritized Intelligence Triage Queue")
        
        # Color coding highlighter helper
        def style_priority(val):
            if val >= 75: return 'background-color: #fee2e2; color: #991b1b; font-weight: bold;'
            elif val >= 50: return 'background-color: #fef3c7; color: #92400e;'
            return 'background-color: #f0fdf4; color: #166534;'

        df_styled = st.session_state.alerts_df.style.applymap(style_priority, subset=['Priority Score'])
        st.dataframe(df_styled, use_container_width=True, height=420)
        
        st.info("💡 Pro-Tip: Select an alert dynamically below to engage LLM Pipeline context mapping.")
        selected_id = st.selectbox("Select Alert Target ID for Commander Briefing Production:", st.session_state.alerts_df["Alert ID"].tolist())
    
    with col_right:
        st.subheader("📋 Executive Threat Profile Builder")
        alert_row = st.session_state.alerts_df[st.session_state.alerts_df["Alert ID"] == selected_id].iloc[0]
        
        # Micro Summary Cards
        c1, c2, c3 = st.columns(3)
        c1.metric("Priority Rating", f"{alert_row['Priority Score']}/100")
        c2.metric("Sensor Target Source", alert_row['Source'])
        c3.metric("Asset Criticality", f"Level {alert_row['Asset Crit']}")
        
        st.write("---")
        
        # Trigger LLM Summarization Action Button
        if st.button("🚀 Generate Automated LLM BLUF Summary", type="primary", use_container_width=True):
            with st.spinner("Executing analytic correlation tools via MCP & Generating BLUF..."):
                payload_details = {
                    "mitre_technique": alert_row["MITRE Technique"],
                    "source": alert_row["Source"],
                    "priority_score": alert_row["Priority Score"]
                }
                bluf_output = generate_bluf_summary(payload_details)
                st.markdown(bluf_output)
                
                # Dynamic Interventions
                st.subheader("⚔️ Recommended Immediate Interventions")
                st.button("🔴 Broadcast Automated Mitigation Playbook", use_container_width=True)

with tab_mitre:
    st.subheader("🗺️ Live Attacker Footprint Heatmap — MITRE ATT&CK Structure")
    st.write("Real-time telemetry tracking mapped dynamically across organizational environments.")
    
    matrix = get_static_mitre_matrix()
    matrix_cols = st.columns(len(matrix.keys()))
    
    for idx, (tactic, techniques) in enumerate(matrix.items()):
        with matrix_cols[idx]:
            st.markdown(f"### **{tactic}**")
            for tech in techniques:
                # Count occurrences in our dynamic alert DataFrame
                match_count = len(st.session_state.alerts_df[st.session_state.alerts_df["MITRE Technique"] == tech])
                if match_count > 0:
                    st.error(f"⚠️ **{tech}** ({match_count} Alerts)")
                else:
                    st.success(f"✔️ {tech}")

with tab_raw:
    st.subheader("🛸 Real-Time Continuous Ingestion Pipeline Simulator")
    st.write("Manually inject unstructured parameters to stress test your correlation engine thresholds.")
    
    with st.form("ingestion_form"):
        f_source = st.selectbox("Telemetry Engine Source Profile", ["SIEM Core", "Orbital Recon Feed", "Perimeter Cyber Sensor", "Human Intercept Intelligence"])
        f_tech = st.selectbox("Observed Signature Fingerprint", list(get_static_mitre_matrix().values())[0] + list(get_static_mitre_matrix().values())[1])
        f_conf = st.slider("Signal Confidence Index (%)", 10, 100, 75)
        f_sev = st.slider("Trigger Severity Weighting", 10, 100, 60)
        f_crit = st.slider("Target Asset Criticality Class", 1, 5, 3)
        
        if st.form_submit_button("📥 Dispatch Stream Vector to Core Ingest Engine"):
            # Compute real time math priority score
            calculated_score = (f_conf * 0.4) + (f_sev * 0.3) + ((f_crit * 20) * 0.3)
            
            # Map tactics
            found_tactic = "Initial Access"
            for tac, techs in get_static_mitre_matrix().items():
                if f_tech in techs:
                    found_tactic = tac
            
            new_row = {
                "Alert ID": f"D2-2026-{1000 + len(st.session_state.alerts_df)}",
                "Timestamp": "2026-09-15 07:20:00",
                "Source": f_source,
                "MITRE Tactic": found_tactic,
                "MITRE Technique": f_tech,
                "Confidence": f_conf,
                "Severity": f_sev,
                "Asset Crit": f_crit,
                "Priority Score": round(calculated_score, 1),
                "Status": "Unassigned"
            }
            
            st.session_state.alerts_df = pd.concat([pd.DataFrame([new_row]), st.session_state.alerts_df], ignore_index=True)
            st.success(f"Ingested and triaged raw log fingerprint! Priority Rating calculated at **{calculated_score:.1f}/100**.")
            st.balloons()
