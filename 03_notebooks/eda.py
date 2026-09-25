import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import json

OUT = "/home/claude/gridwatch/outputs"
FIG = f"{OUT}/figures"

auth = pd.read_csv(f"{OUT}/vendor_auth.csv", parse_dates=["timestamp"])
edr = pd.read_csv(f"{OUT}/edr_telemetry.csv", parse_dates=["timestamp"])
ot = pd.read_csv(f"{OUT}/ot_ids_historian.csv", parse_dates=["timestamp"])

quality_log = {}

# --- Data quality checks ---
for name, df in [("vendor_auth", auth), ("edr_telemetry", edr), ("ot_ids_historian", ot)]:
    nulls = df.isna().sum().sum()
    dupes = df.duplicated().sum()
    quality_log[name] = {
        "rows": len(df),
        "date_range": [str(df["timestamp"].min()), str(df["timestamp"].max())],
        "null_cells": int(nulls),
        "duplicate_rows": int(dupes),
    }

# --- Fig 1: sessions per day + duration distribution ---
auth["date"] = auth["timestamp"].dt.date
daily_sessions = auth.groupby("date").size()

fig, axes = plt.subplots(1, 2, figsize=(12, 4))
daily_sessions.plot(ax=axes[0], marker="o")
axes[0].set_title("Vendor sessions per day")
axes[0].set_ylabel("session count")
axes[0].axvline(pd.Timestamp("2026-08-15").date(), color="red", linestyle="--", alpha=0.6)

auth["session_duration_min"].hist(bins=30, ax=axes[1])
axes[1].set_title("Session duration distribution (all vendors)")
axes[1].set_xlabel("minutes")
plt.tight_layout()
plt.savefig(f"{FIG}/fig1_sessions_overview.png", dpi=110)
plt.close()

# --- Fig 2: logon hour-of-day baseline per account (boxplot-style) ---
auth["hour"] = auth["timestamp"].dt.hour
per_acct_hour = auth.groupby("vendor_account")["hour"].agg(["mean", "std", "count"])

fig, ax = plt.subplots(figsize=(9, 4))
per_acct_hour["mean"].sort_values().plot(kind="barh", xerr=per_acct_hour["std"], ax=ax)
ax.set_title("Baseline logon hour by vendor account (mean ± std)")
ax.set_xlabel("hour of day")
plt.tight_layout()
plt.savefig(f"{FIG}/fig2_hour_baseline_by_account.png", dpi=110)
plt.close()

# --- Fig 3: EDR alert volume/severity over time ---
edr["date"] = edr["timestamp"].dt.date
sev_by_day = edr.groupby(["date", "severity"]).size().unstack(fill_value=0)
fig, ax = plt.subplots(figsize=(10, 4))
sev_by_day.plot(kind="bar", stacked=True, ax=ax, width=0.9)
ax.set_title("EDR alerts per day by severity")
ax.set_xticklabels([str(d) for d in sev_by_day.index], rotation=90, fontsize=6)
plt.tight_layout()
plt.savefig(f"{FIG}/fig3_edr_severity_by_day.png", dpi=110)
plt.close()

# --- Fig 4: OT process deviation over time, highlighting alerts ---
fig, ax = plt.subplots(figsize=(10, 4))
ax.scatter(ot["timestamp"], ot["deviation"], s=6, alpha=0.4, label="normal")
flagged = ot[ot["alert_type"] != "none"]
ax.scatter(flagged["timestamp"], flagged["deviation"], color="red", s=40, label="unauthorized_write_attempt")
ax.set_title("OT process-value deviation from setpoint over case window")
ax.legend()
plt.tight_layout()
plt.savefig(f"{FIG}/fig4_ot_deviation_timeline.png", dpi=110)
plt.close()

summary = {
    "quality_log": quality_log,
    "vendor_accounts": auth["vendor_account"].nunique(),
    "distinct_destination_hosts": auth["destination_host"].nunique(),
    "edr_high_critical_alerts": int((edr["severity"].isin(["High", "Critical"])).sum()),
    "ot_flagged_events": int((ot["alert_type"] != "none").sum()),
    "baseline_session_duration_mean_min": round(float(auth["session_duration_min"].mean()), 1),
    "baseline_session_duration_std_min": round(float(auth["session_duration_min"].std()), 1),
    "baseline_logon_hour_mean": round(float(auth["hour"].mean()), 1),
}

with open(f"{OUT}/metrics/eda_summary.json", "w") as f:
    json.dump(summary, f, indent=2)

print(json.dumps(summary, indent=2))
