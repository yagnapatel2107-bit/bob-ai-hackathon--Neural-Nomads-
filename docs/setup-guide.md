# Setup Guide

Follow these steps exactly — this is written assuming you've never seen
this repo before.

## Prerequisites

- Python 3.9 or newer
- No external packages required — the pipeline only uses Python's standard
  library
- (Optional) An IBM Bob endpoint + API key, only needed for the live
  conversational follow-up feature

## Environment Variables

Copy the example file and fill it in (only required if you want live Bob
integration — the pipeline runs fine without it):

```bash
cd src
cp .env.example .env
```

| Variable | Description |
|---|---|
| `BOB_ENDPOINT` | URL of your IBM Bob deployment's chat endpoint |
| `BOB_API_KEY` | API key/token for that endpoint |
| `FEED_DATA_DIR` | Optional — directory of feed files, defaults to `sample_data` |

## Install

Nothing to install — pure Python standard library.

## Run

```bash
cd src
python3 main.py
```

Expected output: a BLUF-format threat report printed to the console, and
saved to `src/bluf_report.md`.

To run against your own feed data instead of the bundled samples:

```bash
python3 main.py --data-dir /path/to/your/feeds --out /path/to/report.md
```

Feed files must be named `siem_alerts.json`, `satellite_feed.json`,
`cyber_sensors.json`, or `intel_reports.json` and follow the schema shown
in `sample_data/`.

## Verify It's Working

Open `src/bluf_report.md` after running. You should see:

- A count of genuine threat clusters vs. suppressed false positives
- At least one `CRITICAL` or `HIGH` threat cluster (from the bundled
  sample data, which includes a synthetic cross-source phishing → C2 →
  exfiltration chain)
- MITRE ATT&CK technique IDs listed under each threat

## (Optional) Test the Bob Integration

```bash
python3 bob_interface.py
```

Without `BOB_ENDPOINT` configured, this prints a "stub" response showing
exactly what would have been sent to Bob — confirming the integration
point works even without live credentials.

## Troubleshooting

| Error | Fix |
|---|---|
| `python3: command not found` | Try `python` instead of `python3`, or install Python from python.org |
| `FileNotFoundError: sample_data` | Make sure you're inside the `src/` folder when you run the command |
| No output / empty report | Check that your feed JSON files match the exact filenames listed above |
| Bob integration errors out (not stub) | Check `.env` — `BOB_ENDPOINT` and `BOB_API_KEY` must both be set and valid |