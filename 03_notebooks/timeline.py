import pandas as pd
import numpy as np
import json

OUT = "/home/claude/gridwatch/outputs"

auth = pd.read_csv(f"{OUT}/vendor_auth.csv", parse_dates=["timestamp"])
edr = pd.read_csv(f"{OUT}/edr_telemetry.csv", parse_dates=["timestamp"])
ot = pd.read_csv(f"{OUT}/ot_ids_historian.csv", parse_dates=["timestamp"])
uba_flags = pd.read_csv(f"{OUT}/metrics/uba_top_anomalies.csv", parse_dates=["timestamp"])

# Seed the investigation from the highest-confidence UBA-flagged sessions
# for the account under suspicion (analyst workflow: UBA/ML output ->
# investigation, not the reverse).
suspect_account = uba_flags.iloc[0]["vendor_account"]
window_start = uba_flags["timestamp"].min() - pd.Timedelta(hours=1)
window_end = uba_flags["timestamp"].max() + pd.Timedelta(hours=3)

auth_evt = auth[(auth["vendor_account"] == suspect_account) &
                (auth["timestamp"].between(window_start, window_end))].copy()
auth_evt["source"] = "vendor_auth"
auth_evt["description"] = auth_evt.apply(
    lambda r: f"Vendor logon: {r['vendor_account']} -> {r['destination_host']} "
              f"({r['session_duration_min']} min, {r['result']})", axis=1)

edr_evt = edr[(edr["host"].isin(auth_evt["destination_host"].unique())) &
              (edr["timestamp"].between(window_start, window_end)) &
              (edr["severity"].isin(["High", "Critical"]))].copy()
edr_evt["source"] = "edr_telemetry"
edr_evt["description"] = edr_evt.apply(
    lambda r: f"EDR alert on {r['host']}: {r['process']} (parent {r['parent_process']}), "
              f"{r['alert_type']}, severity={r['severity']}", axis=1)

ot_evt = ot[(ot["timestamp"].between(window_start, window_end)) &
            (ot["alert_type"] != "none")].copy()
ot_evt["source"] = "ot_ids_historian"
ot_evt["description"] = ot_evt.apply(
    lambda r: f"OT alert on {r['asset_tag']}: {r['alert_type']}, deviation={r['deviation']}", axis=1)

timeline = pd.concat([
    auth_evt[["event_id", "timestamp", "source", "description"]],
    edr_evt[["event_id", "timestamp", "source", "description"]],
    ot_evt[["event_id", "timestamp", "source", "description"]],
]).sort_values("timestamp").reset_index(drop=True)

timeline.to_csv(f"{OUT}/metrics/correlated_timeline.csv", index=False)

n_sources = timeline["source"].nunique()
n_events = len(timeline)

# Simple confidence scoring: competing-hypothesis test between
# "legitimate maintenance" and "compromise" based on how many distinct
# corroborating evidence types are present.
evidence_types_present = {
    "off_hours_or_atypical_ip": bool((auth_evt["timestamp"].dt.hour < 7).any() or (auth_evt["timestamp"].dt.hour > 18).any()),
    "credential_access_edr_alert": bool((edr_evt["description"].str.contains("credential_access")).any()),
    "defense_evasion_edr_alert": bool((edr_evt["description"].str.contains("defense_evasion")).any()),
    "ot_unauthorized_write": bool((ot_evt["alert_type"] == "unauthorized_write_attempt").any()),
    "lateral_movement_multi_host": auth_evt["destination_host"].nunique() >= 3,
}
n_corroborating = sum(evidence_types_present.values())
confidence = "High" if n_corroborating >= 4 else "Medium" if n_corroborating >= 2 else "Low"

hypothesis_test = {
    "hypothesis_A_legitimate_maintenance": {
        "supported_by": "Vendor account has valid credentials and historical access pattern",
        "contradicted_by": [k for k, v in evidence_types_present.items() if v],
    },
    "hypothesis_B_compromise": {
        "supported_by": [k for k, v in evidence_types_present.items() if v],
        "confidence": confidence,
    },
}

affected = {
    "vendor_account": suspect_account,
    "engineering_hosts_touched": sorted(auth_evt["destination_host"].unique().tolist()),
    "ot_assets_flagged": sorted(ot_evt["asset_tag"].unique().tolist()) if len(ot_evt) else [],
}

containment_actions = [
    "Immediately disable/suspend the vendor account's remote-access credentials pending investigation",
    "Force re-authentication (with MFA) for all other vendor accounts sharing the same jump host",
    "Isolate the affected engineering workstations from the OT network segment pending forensic imaging",
    "Validate PLC/RTU setpoints against known-good configuration and roll back unauthorized changes",
    "Rotate credentials/certificates used on the compromised remote-access pathway",
]

result = {
    "suspect_account": suspect_account,
    "investigation_window": [str(window_start), str(window_end)],
    "n_cross_referenced_events": n_events,
    "n_distinct_sources": n_sources,
    "meets_charter_target(>=6 events, >=3 sources)": bool(n_events >= 6 and n_sources >= 3),
    "affected_users_assets": affected,
    "hypothesis_test": hypothesis_test,
    "overall_confidence": confidence,
    "containment_eradication_recovery_actions": containment_actions,
}

with open(f"{OUT}/metrics/incident_timeline_summary.json", "w") as f:
    json.dump(result, f, indent=2, default=str)

print(json.dumps(result, indent=2, default=str))
print(f"\nTimeline has {n_events} events across {n_sources} sources.")
