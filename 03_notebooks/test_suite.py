"""Lightweight QA test suite for the GridWatch pipeline (Section 13 evidence)."""
import pandas as pd, json, os

OUT = "/home/claude/gridwatch/outputs"
results = []

def record(test_id, component, condition, expected, actual, passed):
    results.append({"test_id": test_id, "component": component, "input_condition": condition,
                     "expected_result": expected, "actual_result": actual,
                     "status": "PASS" if passed else "FAIL"})

# T01: data files exist and are non-empty
for name in ["vendor_auth.csv", "edr_telemetry.csv", "ot_ids_historian.csv", "ground_truth.csv"]:
    path = f"{OUT}/{name}"
    ok = os.path.exists(path) and os.path.getsize(path) > 0
    record(f"T01-{name}", "Data generation", "File should exist and be non-empty",
           "File exists, size > 0", "OK" if ok else "MISSING/EMPTY", ok)

# T02: no nulls/duplicates in raw sources
auth = pd.read_csv(f"{OUT}/vendor_auth.csv")
ok = auth.isna().sum().sum() == 0 and auth.duplicated().sum() == 0
record("T02", "Data quality", "vendor_auth.csv should have no nulls/dupes",
       "0 nulls, 0 duplicates", f"{auth.isna().sum().sum()} nulls, {auth.duplicated().sum()} dupes", ok)

# T03: supervised model results file has all four algorithms' expected keys
with open(f"{OUT}/metrics/supervised_model_results.json") as f:
    sm = json.load(f)
expected_keys = {"precision", "recall", "f1", "roc_auc", "confusion_matrix"}
ok = all(expected_keys.issubset(v.keys()) for v in sm["results"].values())
record("T03", "Supervised ML", "Model results should report full metric set",
       f"Keys present: {expected_keys}", "Present" if ok else "Missing keys", ok)

# T04: UBA recall at threshold should be >0 (i.e. UBA catches at least one true positive)
with open(f"{OUT}/metrics/uba_results.json") as f:
    uba = json.load(f)
ok = uba["recall_of_injected_compromise_at_threshold"] > 0
record("T04", "UBA/anomaly baselining", "UBA should flag at least one true compromised session",
       "recall > 0", f"recall = {uba['recall_of_injected_compromise_at_threshold']}", ok)

# T05: incident timeline meets charter target (>=6 events, >=3 sources)
with open(f"{OUT}/metrics/incident_timeline_summary.json") as f:
    tl = json.load(f)
ok = tl["meets_charter_target(>=6 events, >=3 sources)"]
record("T05", "Incident timeline", "Timeline should meet charter Objective 1 target",
       ">=6 events across >=3 sources",
       f"{tl['n_cross_referenced_events']} events, {tl['n_distinct_sources']} sources", ok)

# T06: simulation shows controls reduce blast radius vs baseline
with open(f"{OUT}/metrics/simulation_results.json") as f:
    sim = json.load(f)
base = sim["scenario_results"]["baseline_no_controls"]["mean_blast_radius"]
combined = sim["scenario_results"]["segmentation_plus_mfa"]["mean_blast_radius"]
ok = combined < base
record("T06", "Simulation", "Combined controls should reduce mean blast radius vs baseline",
       "combined < baseline", f"{combined} < {base}", ok)

# T07: NLP module extracts at least one tactic per document
with open(f"{OUT}/metrics/nlp_textmining_results.json") as f:
    nlp = json.load(f)
ok = all(len(v["tactics_mentioned"]) > 0 for v in nlp["extraction_per_document"].values())
record("T07", "Text mining/NLP", "Every advisory should yield >=1 extracted tactic",
       "all docs >=1 tactic", "OK" if ok else "some docs had 0 tactics", ok)

# T08: at least 3 adversarial cases evaluated
with open(f"{OUT}/metrics/predictive_adversarial_results.json") as f:
    pa = json.load(f)
ok = len(pa["adversarial_cases"]) >= 3
record("T08", "Predictive/adversarial", "Charter requires >=3 adversarial cases",
       ">=3 cases", f"{len(pa['adversarial_cases'])} cases", ok)

df = pd.DataFrame(results)
df.to_csv(f"{OUT}/metrics/test_log.csv", index=False)
print(df.to_string(index=False))
print(f"\n{(df['status']=='PASS').sum()}/{len(df)} tests passed")
