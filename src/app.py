import os
import sys
import streamlit as st

# Ensure src directory is in system path for clean imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend import ThreatIntelligenceEngine

# Streamlit Page Setup
st.set_page_config(
    page_title="Project Bob - Tactical Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Project Bob: Tactical Threat Intelligence Engine")
st.caption("Team Neural-Nomads | Multi-Source Fusion, MITRE ATT&CK Mapping & BLUF Generation")

# Initialize Backend
engine = ThreatIntelligenceEngine()

# Sample Ingestion Data
sample_alerts = [
    {
        "id": "ALT-1001",
        "source": "SATCOM Telemetry",
        "asset_id": "Sector 7 SATCOM Gateway",
        "description": "Hostile actor initiated satcom command-and-control communication with Unix script activity",
        "confidence": 88,
        "priority_score": 85
    },
    {
        "id": "ALT-1002",
        "source": "SIEM Sensor",
        "asset_id": "Internal Relay 3",
        "description": "Routine maintenance health check executed by admin script",
        "confidence": 15,
        "priority_score": 5
    },
    {
        "id": "ALT-1003",
        "source": "Cyber Sensor",
        "asset_id": "Database Relay B",
        "description": "Repeated brute_force logon attempts detected followed by exfiltration outbound traffic",
        "confidence": 92,
        "priority_score": 78
    }
]

# Control Panel
st.sidebar.header("🕹️ Control Panel")
filter_fp = st.sidebar.checkbox("Enable False-Positive Filter", value=True)
run_btn = st.sidebar.button("Run Threat Correlation Pipeline", type="primary")

if run_btn:
    processed = engine.process_pipeline(sample_alerts) if filter_fp else sample_alerts

    # Metrics
    c1, c2, c3 = st.columns(3)
    c1.metric("Raw Ingested Feeds", len(sample_alerts))
    c2.metric("Actionable Threats", len(processed))
    c3.metric("False Positives Dropped", len(sample_alerts) - len(processed))

    st.markdown("---")
    st.subheader("📋 Commander BLUF Briefings")

    for item in processed:
        priority = item.get("priority", "HIGH")
        with st.expander(f"🚨 [{priority}] {item.get('alert_id')} — Source: {item.get('source')}", expanded=True):
            st.error(item.get("bluf", ""))
            st.write(f"**Mapped MITRE ATT&CK TTPs:** `{item.get('mitre_ttps', 'N/A')}`")
            st.write(f"**Recommended Action:** {item.get('recommended_action', 'N/A')}")
else:
    st.info("Click **'Run Threat Correlation Pipeline'** in the sidebar to process telemetry.")