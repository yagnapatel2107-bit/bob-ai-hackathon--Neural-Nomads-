# Solution Overview

## Core Mechanism

Our solution is a four-stage pipeline:

1. **Ingest** — Parsers for each source type (SIEM, satellite, cyber
   sensor, intel report) normalize their native formats into one common
   `Alert` schema, so the rest of the system never has to know or care
   where an alert originated.
2. **Correlate** — Alerts are grouped into threat clusters based on shared
   indicators (IP addresses, domains, file hashes, threat actor names) or
   tight time proximity with overlapping behavior tags. Each cluster is
   scored using explainable, additive factors: alert severity, how many
   *different* source types corroborate it, how many alerts support it,
   and how many MITRE ATT&CK techniques are implicated. Clusters below a
   threshold are treated as likely false positives and suppressed from
   the main report (but kept in an audit trail, not deleted).
3. **MITRE ATT&CK mapping** — Behavior tags on each alert are matched
   against a curated keyword table of MITRE ATT&CK (Enterprise) techniques,
   so every genuine threat cluster is labeled with the specific tactics
   and techniques involved (e.g., T1566 Phishing, T1071 C2, T1486
   Ransomware).
4. **BLUF generation** — Each surviving threat cluster is rendered into
   Bottom Line Up Front format: a one-line verdict and recommended action
   first, followed by supporting evidence — so a commander gets the
   picture in the first sentence and can drill into detail only if needed.

## What Makes It Different From Naive Alternatives

A naive approach would simply list every alert sorted by its own source's
severity label. That fails on two counts: it can't tell you that a
"medium" SIEM alert and a "medium" cyber-sensor alert are actually the
*same* incident, and it treats a lone false-positive "high" alert as more
important than a genuinely corroborated, cross-source incident. Our
correlation step is what turns four disconnected data streams into one
prioritized threat list.

## Key Design Decisions

- **Source diversity is weighted higher than alert count.** Three alerts
  from one noisy sensor are less trustworthy than two alerts from two
  independent source types — the scoring reflects that.
- **Scoring is transparent, not a black box.** Every factor in a cluster's
  score is visible and explainable, because analysts need to trust and
  audit why something was flagged (or suppressed).
- **False positives are suppressed, not discarded.** They stay in an audit
  trail at the bottom of the report so nothing silently disappears.

## User Experience

An analyst or commander runs the pipeline against the day's feeds and
receives a single markdown report: genuine threats first, ranked by
severity, each with a one-line BLUF verdict, supporting evidence, and
mapped ATT&CK techniques — followed by a short list of what was
suppressed and why. IBM Bob sits on top of this report so a commander can
ask natural-language follow-up questions ("why is threat #1 critical?")
and get answers grounded only in that run's data.