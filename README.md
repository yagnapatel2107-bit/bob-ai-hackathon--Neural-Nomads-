# 🚀 Multi-Source Threat Correlation & BLUF Reporting

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | Neural Nomads |
| **Track** | AI |
| **Team Lead** | Yagna Patel — 26aimlcharusat.edu.in |
| **Members** | Dhyey, Het, Sarim |

## 🎯 Problem Statement

Defense analysts receive thousands of alerts daily from SIEM systems, satellite feeds, cyber sensors, and intelligence reports, all in different formats. No human team can read them all, so genuine threats get buried in noise while false positives waste critical response time.

## 💡 Solution

Our pipeline ingests all four feed types into one common alert format, correlates alerts across sources by shared indicators and timing to separate real threats from noise, maps correlated activity to MITRE ATT&CK techniques, and outputs ranked BLUF summaries commanders can act on immediately.

## ✨ Key Features

- **Multi-source ingestion:** Normalizes SIEM, satellite, cyber-sensor, and intel-report data into one schema
- **Correlation engine:** Groups related alerts and scores them to filter out false positives
- **MITRE ATT&CK mapping:** Automatically tags each threat cluster with relevant techniques and tactics
- **BLUF report generation:** Produces commander-ready, prioritized threat summaries
- **IBM Bob / watsonx.ai integration:** MCP server exposes the pipeline as tools; lets commanders ask natural-language follow-up questions grounded in the report

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python |
| **IBM Technologies** | IBM Bob, watsonx.ai (Granite), MCP |

## ⚡ How to Run

```bash
git clone https://github.com/yagnapatel2107-bit/bob-ai-hackathon--Neural-Nomads-.git
cd bob-ai-hackathon--Neural-Nomads-/src
python3 main.py
```

This reads the sample feeds in `sample_data/`, prints a BLUF report, and saves it to `bluf_report.md`.

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/slides.pdf](presentation/) |

## ⚠️ Known Limitations

- MITRE ATT&CK mapping uses a curated keyword table, not the full official dataset
- Demo video link is a placeholder pending final recording
- watsonx.ai integration requires live credentials to move beyond stub mode

## 🏅 What We're Most Proud Of

The correlation engine chains alerts from three different source types (SIEM, cyber sensor, intel report) into a single CRITICAL threat cluster automatically — exactly the kind of connection an overloaded analyst might miss.