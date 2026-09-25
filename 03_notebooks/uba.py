import pandas as pd
import numpy as np
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

OUT = "/home/claude/gridwatch/outputs"
FIG = f"{OUT}/figures"

feat = pd.read_csv(f"{OUT}/vendor_session_features.csv", parse_dates=["timestamp"])
gt = pd.read_csv(f"{OUT}/ground_truth.csv")
data = feat.merge(gt, on="session_id")

# Peer-group baselining: cluster vendor accounts by behavioural profile
# (mean off-hours rate, mean duration z-score, mean lateral reach), then
# flag sessions that deviate from their account's own established baseline
# using a z-score rule (UBA), independent of the supervised model.
acct_profile = data.groupby("vendor_account").agg(
    off_hours_rate=("off_hours_flag", "mean"),
    mean_duration=("session_duration_min", "mean"),
    mean_lateral=("distinct_hosts_48h", "mean"),
).reset_index()

scaler = StandardScaler()
X = scaler.fit_transform(acct_profile[["off_hours_rate", "mean_duration", "mean_lateral"]])
kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
acct_profile["peer_group"] = kmeans.fit_predict(X)

# Rule-based per-session deviation score: sum of |z-scores| across
# duration, hour, and lateral-reach features already computed.
data["uba_deviation_score"] = (
    data["duration_zscore"].abs().fillna(0) +
    data["hour_zscore"].abs().fillna(0) +
    (data["distinct_hosts_48h"] - data["distinct_hosts_48h"].mean()).abs() / data["distinct_hosts_48h"].std()
)

UBA_THRESHOLD = data["uba_deviation_score"].quantile(0.95)
data["uba_flagged"] = (data["uba_deviation_score"] >= UBA_THRESHOLD).astype(int)

flagged = data[data["uba_flagged"] == 1].sort_values("uba_deviation_score", ascending=False)
top_anomalies = flagged[["session_id", "vendor_account", "timestamp", "destination_host",
                          "uba_deviation_score", "is_compromised_session"]].head(15)
top_anomalies.to_csv(f"{OUT}/metrics/uba_top_anomalies.csv", index=False)

# Validate threshold: how many true compromised sessions captured at this cutoff
recall_at_threshold = data.loc[data["is_compromised_session"] == 1, "uba_flagged"].mean()

fig, ax = plt.subplots(figsize=(8, 4))
ax.hist(data.loc[data["is_compromised_session"] == 0, "uba_deviation_score"], bins=30, alpha=0.6, label="normal sessions")
ax.hist(data.loc[data["is_compromised_session"] == 1, "uba_deviation_score"], bins=10, alpha=0.8, label="injected compromise sessions", color="red")
ax.axvline(UBA_THRESHOLD, color="black", linestyle="--", label=f"95th pct threshold={UBA_THRESHOLD:.2f}")
ax.set_xlabel("UBA deviation score"); ax.set_ylabel("session count")
ax.set_title("UBA deviation-score distribution vs. 95th-percentile threshold")
ax.legend()
plt.tight_layout()
plt.savefig(f"{FIG}/fig6_uba_deviation_distribution.png", dpi=110)
plt.close()

summary = {
    "peer_groups": acct_profile.to_dict(orient="records"),
    "uba_threshold_95th_pct": round(float(UBA_THRESHOLD), 3),
    "sessions_flagged": int(data["uba_flagged"].sum()),
    "recall_of_injected_compromise_at_threshold": round(float(recall_at_threshold), 3),
}
with open(f"{OUT}/metrics/uba_results.json", "w") as f:
    json.dump(summary, f, indent=2, default=str)

data.to_csv(f"{OUT}/vendor_session_features.csv", index=False)  # persist uba columns too
print(json.dumps(summary, indent=2, default=str))
print("\nTop anomalies:\n", top_anomalies.to_string(index=False))
