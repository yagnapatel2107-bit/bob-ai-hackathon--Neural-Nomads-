# 🛡️ D2 Threat Intelligence Correlation & Alert Prioritisation Assistant

## 👥 Team Neural Nomads
* **Track:** AI
* **Team Lead:** Yagna Patel (26aimlcharusat.edu.in)
* **Members:** Dhyey, Het, Sarim

---

## 🎯 Problem Statement
Defense analysts face severe alert fatigue, receiving thousands of unstructured security notifications daily across SIEM systems, satellite logs, and cyber sensors. Human teams cannot process this volume in real time. As a result, critical threat signatures get buried under operational background noise, and false positives waste vital defense assets.

## 💡 Solution
We built an intelligent data normalization pipeline and triage scoring engine inside a unified Streamlit dashboard. The application:
1. Normalizes multi-source telemetry logs into a single schema.
2. Applies a mathematical prioritization algorithm to separate true threats from noise.
3. Maps adversary behaviors dynamically to the standard **MITRE ATT&CK Framework**.
4. Hosts a Model Context Protocol (MCP) server that connects with **IBM watsonx.ai** to auto-generate structured, command-ready Bottom Line Up Front (BLUF) briefings for operational commanders.

---

## ⚡ Mathematical Triage Formulation
The engine continuously evaluates threats by weighting raw telemetry indicators against asset criticality thresholds:
$$\text{Priority Score} = (\text{Confidence} \times 0.4) + (\text{Severity} \times 0.3) + (\text{Asset Criticality} \times 20 \times 0.3)$$
Alerts exceeding a score of **75** trigger automated mitigation routing playbooks instantly.

---

## 🛠️ Tech Stack
* **Language:** Python 3.10+
* **Framework:** Streamlit, Pandas, Plotly Express
* **IBM Integration:** watsonx.ai (Granite Foundations), IBM Bob, Model Context Protocol (MCP)

---

## 🚀 Execution Instructions
To test the environment locally, run the following setup commands inside your terminal:
```bash
# Install required libraries
pip install -r src/requirements.txt

# Launch the interactive operations console
streamlit run src/app.py
```

---

## 🏅 Key Achievements
Our correlation layer successfully chains alerts from distinct sensor nodes into an isolated threat matrix automatically—uncovering complex attacker movements that human teams would miss under operational load.
