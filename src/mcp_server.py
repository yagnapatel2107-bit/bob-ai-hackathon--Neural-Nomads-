"""
mcp_server.py
-------------
The Model Context Protocol (MCP) server for this project. This is what
lets IBM Bob / watsonx.ai call our threat-correlation pipeline as a set
of tools, rather than us having to hand-wire a single HTTP endpoint.

Built with the official MCP Python SDK (FastMCP). Exposes three tools:

  1. run_threat_analysis   - runs the full ingest -> correlate -> BLUF
                              pipeline against a feed directory
  2. map_technique_keywords - looks up MITRE ATT&CK techniques for a
                               list of raw keywords/tags
  3. summarize_for_commander - sends a BLUF report to watsonx.ai (Granite)
                               for a short executive summary

Run it directly for local/stdio testing:
    python mcp_server.py

Or point your MCP-compatible client (Bob CLI, Claude Desktop, etc.) at
this script per that client's MCP server configuration docs.
"""

from pathlib import Path
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

from ingest import load_all
from correlate import correlate_alerts, split_genuine_vs_false_positive
from mitre_map import map_keywords_to_techniques
from bluf import generate_report
import watsonx_client

mcp = FastMCP("threat-intel-correlator")


@mcp.tool()
def run_threat_analysis(data_dir: str = "sample_data") -> str:
    """Run the full pipeline (ingest -> correlate -> MITRE map -> BLUF)
    against a directory of feed files and return the BLUF report as
    markdown.

    Args:
        data_dir: Path to a directory containing siem_alerts.json,
            satellite_feed.json, cyber_sensors.json, and/or
            intel_reports.json. Defaults to the bundled sample data.
    """
    path = Path(data_dir)
    if not path.exists():
        return f"Error: data directory '{data_dir}' does not exist."

    alerts = load_all(path)
    if not alerts:
        return f"No alerts found in '{data_dir}'. Check filenames match the expected schema."

    clusters = correlate_alerts(alerts)
    genuine, false_positives = split_genuine_vs_false_positive(clusters)
    return generate_report(genuine, false_positives)


@mcp.tool()
def map_technique_keywords(keywords: List[str]) -> str:
    """Map a list of raw alert keywords/behavior tags to MITRE ATT&CK
    techniques (id, name, tactic).

    Args:
        keywords: Raw tags from an alert, e.g. ["beacon", "encoded_command"]
    """
    techniques = map_keywords_to_techniques(keywords)
    if not techniques:
        return "No matching MITRE ATT&CK techniques found for these keywords."
    lines = [f"- {t['id']} {t['name']} ({t['tactic']})" for t in techniques]
    return "\n".join(lines)


@mcp.tool()
def summarize_for_commander(bluf_report: str) -> str:
    """Send a BLUF report to watsonx.ai (Granite) and return a 2-3
    sentence executive summary for a commander. Falls back to a plain
    notice if watsonx.ai credentials aren't configured, so the tool never
    hard-fails a demo.

    Args:
        bluf_report: The markdown BLUF report text, e.g. the output of
            run_threat_analysis.
    """
    try:
        return watsonx_client.summarize_bluf_report(bluf_report)
    except watsonx_client.WatsonxNotConfigured as e:
        return f"[watsonx.ai not configured — {e}] Returning report as-is:\n\n{bluf_report[:500]}..."
    except Exception as e:
        return f"[watsonx.ai request failed: {e}]"


if __name__ == "__main__":
    # Runs over stdio by default, the standard transport MCP clients expect
    # for locally-launched servers.
    mcp.run()
