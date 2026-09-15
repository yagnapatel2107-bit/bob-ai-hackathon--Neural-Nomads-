# Contributing to Project Bob

Welcome to the **Project Bob: Multi-Source Threat Fusion Engine** repository! This document outlines team roles, local development guidelines, and pull request procedures for team **Neural-Nomads**.

---

## 👥 Team Roles & Responsibilities

* **Yagna Patel (Team Lead)**: Architecture, Integration Lead, GitHub Actions workflows, `submission.yaml`, and repo maintenance.
* **Dhyeykumar Trivedi**: Backend Core Logic, Data Ingestion pipelines, and MITRE ATT&CK mapping engine (`src/backend.py`).
* **Het Ramanuj**: UI/UX Development, Streamlit Dashboard (`src/App.py`), Slides, and Demo Media.
* **Sarim Saiyad**: Documentation (`docs/`), QA Testing, Setup Instructions, and Placeholder Audits.

---

## 🚀 Local Development Setup

### 1. Repository Setup

```bash
# Clone the repository
git clone [https://github.com/yagnapatel2107-bit/bob-ai-hackathon--Neural-Nomads-.git](https://github.com/yagnapatel2107-bit/bob-ai-hackathon--Neural-Nomads-.git)
cd bob-ai-hackathon--Neural-Nomads-

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r src/requirements.txt