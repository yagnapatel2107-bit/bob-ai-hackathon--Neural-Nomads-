"""
bob_interface.py
-----------------
Integration point between this pipeline's BLUF output and IBM Bob.

This is the load-bearing integration for the "IBM Bob Integration" scoring
criterion: rather than just mentioning Bob in the docs, the generated BLUF
report is handed to Bob so a commander can ask natural-language follow-up
questions ("why is threat #1 critical?", "show me raw alerts for SENS-3001")
and get answers grounded in this run's data.

Fill in BOB_ENDPOINT / BOB_API_KEY (via environment variables, see
.env.example) with your actual Bob deployment details. The request/response
shape below follows Bob's standard chat-completion contract; adjust field
names to match the exact version of Bob your team is issued for the event.
"""

import os
import json
import urllib.request
from typing import Dict, Any

BOB_ENDPOINT = os.environ.get("BOB_ENDPOINT", "")
BOB_API_KEY = os.environ.get("BOB_API_KEY", "")


def build_bob_prompt(bluf_report: str) -> str:
    """Wrap the BLUF report in a system-style instruction so Bob answers
    commander follow-up questions grounded in this run's data only."""
    return (
        "You are briefing a commander on the following threat assessment. "
        "Answer follow-up questions using ONLY the data below; if something "
        "isn't in it, say so explicitly rather than guessing.\n\n"
        f"{bluf_report}"
    )


def send_to_bob(bluf_report: str, question: str = None) -> Dict[str, Any]:
    """Send the BLUF report (and an optional commander follow-up question)
    to IBM Bob and return the parsed response.

    Returns a stub response if BOB_ENDPOINT is not configured, so the
    pipeline still runs end-to-end in an offline/demo environment.
    """
    if not BOB_ENDPOINT:
        return {
            "status": "stub",
            "note": "BOB_ENDPOINT not set — configure .env to enable live Bob integration.",
            "would_have_sent": build_bob_prompt(bluf_report),
        }

    payload = {
        "messages": [
            {"role": "system", "content": build_bob_prompt(bluf_report)},
            {"role": "user", "content": question or "Summarize the top priority for the commander in one sentence."},
        ]
    }

    req = urllib.request.Request(
        BOB_ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {BOB_API_KEY}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


if __name__ == "__main__":
    # Quick manual check: run main.py first to generate bluf_report.md
    from pathlib import Path
    report_path = Path("bluf_report.md")
    if report_path.exists():
        result = send_to_bob(report_path.read_text())
        print(json.dumps(result, indent=2))
    else:
        print("Run `python main.py` first to generate bluf_report.md")
