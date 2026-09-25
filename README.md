# T07 · GridWatch
Vendor-Pathway IT/OT Compromise Investigation and Predictive Security Analytics
SAS821S Capstone — Group T07 — Gideon Kalimbo (222101881) & Shikulo Tangeni (223016179)

## What this project does
Investigates a suspected compromise of vendor remote-access account `VEND-ACME-03`
across three telemetry sources (vendor authentication, EDR, OT/IDS historian),
builds a supervised + unsupervised detection layer, correlates the evidence into
a single incident timeline, simulates the effect of competing security controls,
mines open threat-intelligence text for corroborating indicators, and produces a
governed, adversarially-tested predictive risk score for future vendor sessions.
A parallel R implementation independently validates four of these components
(UBA, simulation, text mining, decision-tree adversarial testing) against the
primary Python pipeline — see `03_notebooks/` for both.

## Folder guide

| Folder | Contents | Status |
|---|---|---|
| `01_charter/` | Project charter | Complete |
| `02_data/raw/` | Unmodified source telemetry: vendor_auth, edr_telemetry, ot_ids_historian, ground_truth, threat_intel/ | Complete |
| `02_data/processed/` | Derived/feature tables: vendor_session_features, correlated_timeline, test_log | Complete |
| `03_notebooks/` | Primary Python pipeline (architecture_diagram, eda, generate_data, generate_threat_intel, nlp_textmining, predictive_adversarial, simulation, supervised_model, test_suite, timeline, uba) plus independent R validation scripts (uba_workflow.R, rscript_for_simulation.r, adversarial_decision_tree.R) | Complete — see note below on rnotebook_text_mining.md |
| `04_models/` | Supervised model + UBA results (Python and R) and flagged sessions | Complete |
| `05_simulation/` | Monte Carlo control-scenario simulation results (Python, 200 iter; R, 1000 iter) | Complete |
| `06_text_mining/` | NLP/threat-intel extraction results | Pipeline complete — corpus is 20 documents, within the charter's 15–30 target |
| `07_dashboard/` | Local dashboard prototype | Complete |
| `08_outputs/` | Final integrated outputs: incident timeline summary, EDA summary, predictive/adversarial results, full figure set (fig0–fig8) | Complete |
| `09_documentation/` | Implementation plan | **Incomplete — see below** |

## Known gaps before submission

- **`03_notebooks/rnotebook_text_mining.md`** is currently a raw console-paste of
  the placeholder seed corpus, not the finished `text_mining_workflow.R` script.
  Replace it with the actual script file.
- **`09_documentation/` is missing three files** that exist and are ready to add:
  - `GridWatch_Final_Report.pdf` (and/or `.docx`) — the Milestone 3 submission itself
  - `GridWatch_Sessions1-10_Evidence_Audit.docx`
  - `GridWatch_Session5_and_3-4_Closure.docx`

## Environment
See `requirements.txt` (Python) and `project.Rproj` (R).

## Repository
Hosted at github.com/223016179/GROUP_T07_GridWatch.
