
# SmartOps Threat Intelligence Assistant (Powered by IBM Bob)

**Track:** AI  
**Team:** Yagna Patel (Lead), Dhyey, Het, Sarim  

## 🚨 Problem Statement
Defense analysts and Security Operations Centers (SOCs) receive thousands of daily alerts from disparate sources, including SIEM systems, satellite feeds, and cyber sensors. Missing a genuine threat can lead to catastrophic breaches, but manually chasing false positives wastes critical response time and resources. Commanders currently lack rapid, structured visibility into high-priority threats.

## 💡 Solution
We built an IBM Bob Copilot that ingests and correlates multi-source threat feeds in real-time. By mapping attacker behaviors directly to the MITRE ATT&CK framework, the system separates genuine threats from false positives and auto-generates Bottom Line Up Front (BLUF) summaries for military commanders.

## ✨ Key Features
* **Multi-Source Ingestion:** Unified correlation of SIEM, satellite, and cyber sensor alerts.
* **Intelligent Triage:** Automated separation of critical threats from false positives using watsonx.ai.
* **MITRE ATT&CK Mapping:** Direct alignment of adversary techniques to the industry-standard threat framework.
* **BLUF Generation:** Instant, structured executive summaries for rapid commander decision-making.

## 🛠 Tech Stack
* **AI & Logic:** IBM Bob CLI, watsonx.ai (Granite 3.0), MCP SDK
* **Backend:** Python, FastAPI, PostgreSQL
* **Frontend:** React, Tailwind CSS

## 🚀 How to Run
Please see our complete setup instructions in `docs/setup-guide.md`.

## 🎥 Demo & Media
* **Live Demo Video:** [Not Deployed]
* **Screenshots:** Available in the `demo/screenshots/` directory.

## ⚠️ Known Limitations
* The current version uses simulated SIEM logs; live satellite feed integration is mocked for the hackathon environment.

