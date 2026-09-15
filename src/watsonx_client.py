"""
watsonx_client.py
------------------
Thin wrapper around the IBM watsonx.ai text-generation REST API
(Granite models). Used by mcp_server.py to turn a raw BLUF report into a
short executive summary a commander can read in one glance.

Auth flow: IBM Cloud IAM token exchange (API key -> bearer token), then a
POST to the watsonx.ai /ml/v1/text/generation endpoint. See:
https://cloud.ibm.com/apidocs/watsonx-ai
"""

import os
import json
import time
import urllib.request
import urllib.error

IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"
WATSONX_URL = os.environ.get("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
WATSONX_API_KEY = os.environ.get("WATSONX_API_KEY", "")
WATSONX_PROJECT_ID = os.environ.get("WATSONX_PROJECT_ID", "")
MODEL_ID = os.environ.get("WATSONX_MODEL_ID", "ibm/granite-3-8b-instruct")

_token_cache = {"value": None, "expires_at": 0}


class WatsonxNotConfigured(Exception):
    pass


def _get_iam_token() -> str:
    """Exchange the API key for a short-lived bearer token, cached until it expires."""
    if not WATSONX_API_KEY:
        raise WatsonxNotConfigured("WATSONX_API_KEY is not set in the environment.")

    if _token_cache["value"] and time.time() < _token_cache["expires_at"]:
        return _token_cache["value"]

    data = (
        f"grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey={WATSONX_API_KEY}"
    ).encode("utf-8")
    req = urllib.request.Request(
        IAM_TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    _token_cache["value"] = payload["access_token"]
    _token_cache["expires_at"] = time.time() + int(payload.get("expires_in", 3600)) - 60
    return _token_cache["value"]


def summarize_bluf_report(report_markdown: str, max_new_tokens: int = 200) -> str:
    """Ask a watsonx.ai Granite model for a 2-3 sentence executive summary
    of a BLUF report. Raises WatsonxNotConfigured if credentials are missing
    so callers (e.g. the MCP tool) can fall back gracefully."""
    if not WATSONX_API_KEY or not WATSONX_PROJECT_ID:
        raise WatsonxNotConfigured(
            "WATSONX_API_KEY and WATSONX_PROJECT_ID must both be set in .env"
        )

    token = _get_iam_token()

    prompt = (
        "You are briefing a commander. In 2-3 sentences, give the single "
        "most urgent takeaway from this threat assessment and the one "
        "action they should take right now. Be direct, no preamble.\n\n"
        f"{report_markdown}\n\nExecutive summary:"
    )

    body = {
        "model_id": MODEL_ID,
        "project_id": WATSONX_PROJECT_ID,
        "input": prompt,
        "parameters": {
            "decoding_method": "greedy",
            "max_new_tokens": max_new_tokens,
            "repetition_penalty": 1.1,
        },
    }

    req = urllib.request.Request(
        f"{WATSONX_URL}/ml/v1/text/generation?version=2024-05-01",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"watsonx.ai request failed ({e.code}): {e.read().decode('utf-8')}")

    return result["results"][0]["generated_text"].strip()
