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

## Folder guide

| Folder | Contents | Status |
|---|---|---|
| `01_charter/` | Project charter | Complete |
| `02_data/raw/` | Unmodified source telemetry: vendor_auth, edr_telemetry, ot_ids_historian, ground_truth | Complete |
| `02_data/processed/` | Derived/feature tables: vendor_session_features, correlated_timeline, test_log | Complete |
| `03_notebooks_or_scripts/` | Analysis scripts (supervised_model.py, uba.py, timeline.py, simulation.py, nlp_textmining.py, predictive_adversarial.py, generate_threat_intel.py) | **Not yet added — see below** |
| `04_models/` | Supervised model + UBA results and flagged sessions | Complete |
| `05_simulation/` | Monte Carlo control-scenario simulation results | Complete |
| `06_text_mining/` | NLP/threat-intel extraction results | Complete (corpus expansion still pending — see the evidence audit in `09_documentation/`) |
| `07_dashboard_or_prototype/` | Local dashboard prototype | **Not yet added — see below** |
| `08_outputs/` | Final integrated outputs: incident timeline summary, EDA summary, predictive/adversarial results | Complete |
| `09_documentation/` | Capstone brief, implementation plan, Sessions 1–10 evidence audit | Complete |

## Known gaps before submission
This bundle was assembled from the result files and PDFs available in this
session — it does not have access to your local filesystem or GitHub. Two
folders are currently empty and need to be populated by you before the
9-folder structure is genuinely complete:

- **`03_notebooks_or_scripts/`** — copy in the actual `.py`/`.Rmd` scripts that
  produced each result file (named in the implementation plan but not
  supplied as files to this session).
- **`07_dashboard_or_prototype/`** — copy in the local dashboard prototype
  (referenced in the implementation plan as a local `index.html`).

See `09_documentation/GridWatch_Sessions1-10_Evidence_Audit.docx` for the full
session-by-session evidence audit, including the NLP corpus-size gap and
other closure items.

## Environment
See `requirements.txt`. Verify this list against your own script imports —
it is reconstructed from the analysis techniques evidenced in the result
files, not exported from your actual environment.

## Repository
A GitHub repository is recommended by the brief and still pending — push this
structure there with both members added as collaborators before submission.
