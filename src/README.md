# src/ — Source Code Layout

Pure Python 3.9+, no external dependencies required to run the core pipeline.

| File | Purpose |
|---|---|
| `ingest.py` | Normalizes SIEM, satellite, cyber-sensor, and intel-report feeds into one common `Alert` schema |
| `mitre_map.py` | Keyword-based mapping from alert tags to MITRE ATT&CK techniques |
| `correlate.py` | Groups alerts into threat clusters by shared indicators/time proximity; scores genuine vs. false positive |
| `bluf.py` | Renders scored clusters into BLUF (Bottom Line Up Front) markdown for commanders |
| `bob_interface.py` | Hands the finished BLUF report to IBM Bob for natural-language commander Q&A |
| `main.py` | CLI entry point — wires the pipeline together |
| `sample_data/` | Synthetic multi-source feed data used for the demo |

## Run it

```bash
cd src
python3 main.py
```

This reads `sample_data/`, prints the BLUF report to the console, and saves it to `bluf_report.md`.

To point at your own feeds:

```bash
python3 main.py --data-dir /path/to/feeds --out /path/to/output.md
```

Feed files must be named `siem_alerts.json`, `satellite_feed.json`, `cyber_sensors.json`,
or `intel_reports.json` and follow the schema shown in `sample_data/`.

To enable live Bob follow-up Q&A, copy `.env.example` to `.env`, fill in `BOB_ENDPOINT`
and `BOB_API_KEY`, then run:

```bash
python3 bob_interface.py
```
