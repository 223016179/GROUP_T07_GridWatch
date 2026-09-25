"""
GridWatch synthetic data generator.

Generates three internally-consistent, purely synthetic datasets for a
28-day case window, with a single injected vendor-pathway compromise
scenario embedded in the middle of the window. No real vendor, utility,
or malware data is used anywhere (see Project Charter Section 6).

Outputs (to ../outputs/):
  vendor_auth.csv        - vendor remote-access authentication logs
  edr_telemetry.csv      - endpoint detection & response events
  ot_ids_historian.csv   - OT IDS alerts + historian process values
  ground_truth.csv       - per-session compromise label (for model eval only,
                            NOT used as a feature - this is the "answer key")
"""
import numpy as np
import importlib
from datetime import datetime, timedelta

pd = importlib.import_module("pandas")

rng = np.random.default_rng(42)

CASE_START = datetime(2026, 8, 1, 0, 0, 0)
CASE_DAYS = 28
COMPROMISE_START = CASE_START + timedelta(days=14, hours=1, minutes=10)
COMPROMISE_END = COMPROMISE_START + timedelta(hours=30)  # ~1.25 day dwell

VENDOR_ACCOUNTS = [f"VEND-{name}-{n:02d}" for name, n in
                   [("ACME", 1), ("ACME", 2), ("ACME", 3),
                    ("PLC-SVC", 1), ("PLC-SVC", 2),
                    ("TURBOMAINT", 1), ("TURBOMAINT", 2)]]
COMPROMISED_ACCOUNT = "VEND-ACME-03"

ENGINEERING_HOSTS = [f"ENG-WKS-{n:02d}" for n in range(1, 6)]
HISTORIAN_HOST = "HIST-SRV-01"
JUMP_HOST = "JUMP-OT-01"
ALL_DEST_HOSTS = [JUMP_HOST] + ENGINEERING_HOSTS + [HISTORIAN_HOST]

OT_ASSETS = [f"RTU-{n:02d}" for n in range(1, 9)] + [f"PLC-{n:02d}" for n in range(1, 7)]
PROTOCOLS = ["Modbus", "DNP3"]

# 1. Vendor remote-access authentication logs
def business_hour_timestamp(day_offset):
    day = CASE_START + timedelta(days=int(day_offset))
    hour = int(np.clip(rng.normal(13, 2.5), 7, 18))
    minute = rng.integers(0, 60)
    return day + timedelta(hours=hour, minutes=int(minute))

auth_rows = []
session_id_counter = 1

for day in range(CASE_DAYS):
    # normal maintenance activity: 8-15 sessions/day across vendor accounts
    n_sessions = rng.integers(8, 16)
    for _ in range(n_sessions):
        acct = rng.choice(VENDOR_ACCOUNTS)
        ts = business_hour_timestamp(day)
        dest = rng.choice([JUMP_HOST] + ENGINEERING_HOSTS, p=[0.55] + [0.09]*5)
        duration = int(np.clip(rng.normal(22, 10), 3, 90))  # minutes
        auth_rows.append({
            "session_id": f"S{session_id_counter:05d}",
            "timestamp": ts,
            "vendor_account": acct,
            "source_ip": f"203.0.113.{rng.integers(10,60)}",
            "destination_host": dest,
            "logon_type": "RemoteInteractive",
            "result": "Success" if rng.random() > 0.03 else "Failure",
            "session_duration_min": duration,
        })
        session_id_counter += 1

# Injected compromise: VEND-ACME-03 off-hours logons, longer sessions,
# unusual lateral reach to multiple engineering workstations, then historian.
compromise_events = [
    (COMPROMISE_START, JUMP_HOST, 140),
    (COMPROMISE_START + timedelta(hours=3, minutes=20), "ENG-WKS-02", 95),
    (COMPROMISE_START + timedelta(hours=6, minutes=5), "ENG-WKS-04", 110),
    (COMPROMISE_START + timedelta(hours=20, minutes=15), HISTORIAN_HOST, 65),
    (COMPROMISE_START + timedelta(hours=27, minutes=40), "ENG-WKS-02", 40),
]
for ts, dest, duration in compromise_events:
    auth_rows.append({
        "session_id": f"S{session_id_counter:05d}",
        "timestamp": ts,
        "vendor_account": COMPROMISED_ACCOUNT,
        "source_ip": "198.51.100.77",  # different from normal ACME range
        "destination_host": dest,
        "logon_type": "RemoteInteractive",
        "result": "Success",
        "session_duration_min": duration,
    })
    session_id_counter += 1

auth_df = pd.DataFrame(auth_rows).sort_values("timestamp").reset_index(drop=True)
auth_df["event_id"] = [f"AUTH-{i+1:05d}" for i in range(len(auth_df))]

# ----------------------------------------------------------------------
# 2. EDR telemetry
# ----------------------------------------------------------------------
NORMAL_PROCS = [
    ("TeamViewer_Host.exe", "explorer.exe", "benign"),
    ("plc_config_tool.exe", "TeamViewer_Host.exe", "benign"),
    ("patch_deploy.exe", "svchost.exe", "benign"),
]
edr_rows = []
edr_counter = 1
for day in range(CASE_DAYS):
    n_events = rng.integers(15, 30)
    for _ in range(n_events):
        host = rng.choice(ENGINEERING_HOSTS + [JUMP_HOST])
        ts = business_hour_timestamp(day)
        proc, parent, alert_type = NORMAL_PROCS[rng.integers(0, len(NORMAL_PROCS))]
        edr_rows.append({
            "event_id": f"EDR-{edr_counter:05d}",
            "timestamp": ts, "host": host, "process": proc, "parent_process": parent,
            "hash": f"sha256:{rng.integers(10**15,10**16-1):x}",
            "alert_type": alert_type, "severity": "Info",
        })
        edr_counter += 1

# Injected compromise EDR signal: credential-access-style tool execution,
# staging/exfil-style archive utility, and disabling of local logging -
# named generically, no operational technique detail.
compromise_edr = [
    (COMPROMISE_START + timedelta(minutes=25), JUMP_HOST, "cred_dump_tool.exe", "svchost.exe", "credential_access", "High"),
    (COMPROMISE_START + timedelta(hours=3, minutes=40), "ENG-WKS-02", "archive_stager.exe", "cred_dump_tool.exe", "collection_staging", "High"),
    (COMPROMISE_START + timedelta(hours=6, minutes=15), "ENG-WKS-04", "logging_disable.bat", "cmd.exe", "defense_evasion", "Critical"),
    (COMPROMISE_START + timedelta(hours=20, minutes=25), HISTORIAN_HOST, "archive_stager.exe", "cred_dump_tool.exe", "collection_staging", "High"),
]
for ts, host, proc, parent, alert_type, sev in compromise_edr:
    edr_rows.append({
        "event_id": f"EDR-{edr_counter:05d}",
        "timestamp": ts, "host": host, "process": proc, "parent_process": parent,
        "hash": f"sha256:{rng.integers(10**15,10**16-1):x}",
        "alert_type": alert_type, "severity": sev,
    })
    edr_counter += 1

edr_df = pd.DataFrame(edr_rows).sort_values("timestamp").reset_index(drop=True)

# ----------------------------------------------------------------------
# 3. OT IDS alerts + historian process values
# ----------------------------------------------------------------------
ot_rows = []
ot_counter = 1
for day in range(CASE_DAYS):
    n_events = rng.integers(40, 70)
    for _ in range(n_events):
        asset = rng.choice(OT_ASSETS)
        ts = CASE_START + timedelta(days=day, hours=int(rng.integers(0,24)), minutes=int(rng.integers(0,60)))
        setpoint = round(rng.normal(50, 3), 2)
        value = round(setpoint + rng.normal(0, 0.8), 2)
        ot_rows.append({
            "event_id": f"OT-{ot_counter:05d}",
            "timestamp": ts, "asset_tag": asset,
            "protocol": rng.choice(PROTOCOLS),
            "alert_type": "none",
            "process_value": value, "setpoint": setpoint,
            "deviation": round(value - setpoint, 2),
        })
        ot_counter += 1

# Injected compromise OT signal: unauthorized setpoint write attempts and
# process-value deviation on assets reachable from ENG-WKS-04 / historian
compromise_ot = [
    (COMPROMISE_START + timedelta(hours=6, minutes=30), "PLC-03", 12.5),
    (COMPROMISE_START + timedelta(hours=6, minutes=45), "PLC-03", 14.1),
    (COMPROMISE_START + timedelta(hours=20, minutes=40), "RTU-05", 9.8),
    (COMPROMISE_START + timedelta(hours=27, minutes=55), "PLC-03", 11.0),
]
for ts, asset, dev in compromise_ot:
    setpoint = 50.0
    ot_rows.append({
        "event_id": f"OT-{ot_counter:05d}",
        "timestamp": ts, "asset_tag": asset,
        "protocol": "Modbus",
        "alert_type": "unauthorized_write_attempt",
        "process_value": round(setpoint + dev, 2), "setpoint": setpoint,
        "deviation": dev,
    })
    ot_counter += 1

ot_df = pd.DataFrame(ot_rows).sort_values("timestamp").reset_index(drop=True)

# ----------------------------------------------------------------------
# Ground truth (evaluation only - not a feature)
# ----------------------------------------------------------------------
auth_df["is_compromised_session"] = (
    (auth_df["vendor_account"] == COMPROMISED_ACCOUNT) &
    (auth_df["timestamp"] >= COMPROMISE_START) &
    (auth_df["timestamp"] <= COMPROMISE_END)
).astype(int)

ground_truth = auth_df[["session_id", "is_compromised_session"]].copy()

# ----------------------------------------------------------------------
# Persist
# ----------------------------------------------------------------------
out = "/home/claude/gridwatch/outputs"
auth_df.drop(columns=["is_compromised_session"]).to_csv(f"{out}/vendor_auth.csv", index=False)
edr_df.to_csv(f"{out}/edr_telemetry.csv", index=False)
ot_df.to_csv(f"{out}/ot_ids_historian.csv", index=False)
ground_truth.to_csv(f"{out}/ground_truth.csv", index=False)

print(f"vendor_auth: {len(auth_df)} rows ({auth_df['is_compromised_session'].sum()} compromised sessions)")
print(f"edr_telemetry: {len(edr_df)} rows")
print(f"ot_ids_historian: {len(ot_df)} rows")
print(f"Compromise window: {COMPROMISE_START} -> {COMPROMISE_END}")
print(f"Compromised account: {COMPROMISED_ACCOUNT}")
