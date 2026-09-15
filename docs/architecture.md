# Architecture

## System Diagram

'''mermaid
graph TD
    A[SIEM Feed] --> E[ingest.py]
    B[Satellite Feed] --> E
    C[Cyber Sensor Feed] --> E
    D[Intel Reports] --> E
    E -->|Normalized Alerts| F[correlate.py]
    F -->|Threat Clusters + Scores| G[mitre_map.py]
    G -->|ATT&CK-tagged Clusters| H[bluf.py]
    H -->|BLUF Report| I[bob_interface.py]
    I -->|Report + Q&A| J[Commander]
'''

## Component Table

| Component | Technology | Responsibility |
|---|---|---|
| `ingest.py` | Python (stdlib `json`) | Parses each source's native format into a common `Alert` schema |
| `mitre_map.py` | Python (keyword lookup table) | Maps alert behavior tags to MITRE ATT&CK techniques and tactics |
| `correlate.py` | Python | Groups alerts into threat clusters by shared indicators/time proximity; scores genuine vs. false positive |
| `bluf.py` | Python | Renders scored clusters into BLUF-format markdown |
| `bob_interface.py` | Python (`urllib`) | Sends the finished report to IBM Bob for natural-language commander Q&A |
| `main.py` | Python (`argparse`) | CLI entry point that wires the pipeline stages together |

## Data Flow, End to End

1. Raw feed files (JSON) land in `sample_data/` (or a live feed directory).
2. `main.py` calls `ingest.load_all()`, which reads each file and returns a
   list of normalized `Alert` objects.
3. `correlate.correlate_alerts()` sorts alerts by time and unions them into
   `ThreatCluster` objects based on shared indicators or time-windowed tag
   overlap, then scores each cluster.
4. `correlate.split_genuine_vs_false_positive()` separates clusters above
   and below the score threshold.
5. `bluf.generate_report()` renders both lists into a single markdown
   report, with false positives kept in an audit-trail section.
6. `main.py` writes the report to disk and prints it; `bob_interface.py`
   can optionally forward it to IBM Bob for conversational follow-up.

## Security & Scalability Notes

- No real credentials are stored in the repo — `.env.example` documents
  required variables, and the actual `.env` is git-ignored.
- The correlation step is O(n × clusters) per alert, which is fine at
  hackathon scale; a production version would index alerts by indicator
  in a hash map rather than scanning existing clusters linearly.
- The MITRE mapping table is a simple, auditable keyword lookup rather
  than a full STIX/TAXII client — noted as a known limitation, with the
  interface designed so it can be swapped in without changing callers.