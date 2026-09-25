import pandas as pd
import numpy as np
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (confusion_matrix, precision_score, recall_score,
                              f1_score, roc_auc_score, roc_curve)

OUT = "/home/claude/gridwatch/outputs"
FIG = f"{OUT}/figures"

auth = pd.read_csv(f"{OUT}/vendor_auth.csv", parse_dates=["timestamp"])
edr = pd.read_csv(f"{OUT}/edr_telemetry.csv", parse_dates=["timestamp"])
gt = pd.read_csv(f"{OUT}/ground_truth.csv")

# ----------------------------------------------------------------------
# Feature engineering (session-level). LEAKAGE CONTROL: every feature is
# derived only from information available at/around session time from the
# IT-side logs (auth + EDR within +/- 2h of the session). The ground-truth
# label itself, and any OT-side outcome, is NEVER used as a feature - it
# is held out purely for evaluation, mirroring a real SOC where the OT
# impact would not yet be confirmed at triage time.
# ----------------------------------------------------------------------
auth["hour"] = auth["timestamp"].dt.hour
acct_baseline = auth.groupby("vendor_account").agg(
    baseline_hour_mean=("hour", "mean"),
    baseline_hour_std=("hour", "std"),
    baseline_duration_mean=("session_duration_min", "mean"),
    baseline_duration_std=("session_duration_min", "std"),
).reset_index()
acct_baseline = acct_baseline.fillna(acct_baseline.mean(numeric_only=True))

feat = auth.merge(acct_baseline, on="vendor_account", how="left")
feat["off_hours_flag"] = (~feat["hour"].between(7, 18)).astype(int)
feat["hour_zscore"] = (feat["hour"] - feat["baseline_hour_mean"]) / feat["baseline_hour_std"].replace(0, 1)
feat["duration_zscore"] = (feat["session_duration_min"] - feat["baseline_duration_mean"]) / feat["baseline_duration_std"].replace(0, 1)
feat["failed_logon"] = (feat["result"] == "Failure").astype(int)

# distinct destination hosts touched by this account in the surrounding 48h
feat = feat.sort_values("timestamp")
lateral_counts = []
for _, row in feat.iterrows():
    window = feat[(feat["vendor_account"] == row["vendor_account"]) &
                  (feat["timestamp"] >= row["timestamp"] - pd.Timedelta(hours=48)) &
                  (feat["timestamp"] <= row["timestamp"])]
    lateral_counts.append(window["destination_host"].nunique())
feat["distinct_hosts_48h"] = lateral_counts

# EDR alerts on the same host within +/- 2 hours of the session
def edr_alerts_near(row):
    window = edr[(edr["host"] == row["destination_host"]) &
                 (edr["timestamp"] >= row["timestamp"] - pd.Timedelta(hours=2)) &
                 (edr["timestamp"] <= row["timestamp"] + pd.Timedelta(hours=2))]
    return pd.Series({
        "edr_alerts_near": len(window),
        "edr_high_crit_near": int(window["severity"].isin(["High", "Critical"]).sum()),
    })

edr_feats = feat.apply(edr_alerts_near, axis=1)
feat = pd.concat([feat, edr_feats], axis=1)

FEATURES = ["off_hours_flag", "hour_zscore", "duration_zscore", "failed_logon",
            "distinct_hosts_48h", "edr_alerts_near", "edr_high_crit_near"]

data = feat.merge(gt, on="session_id")
X = data[FEATURES].fillna(0)
y = data["is_compromised_session"]

print(f"Total sessions: {len(data)}, positive (compromised): {y.sum()}")

# Stratified 70/30 split, fixed seed (per charter Section 7)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, stratify=y, random_state=42
)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

results = {}
models = {
    "logistic_regression": LogisticRegression(class_weight="balanced", random_state=42, max_iter=1000),
    "decision_tree": DecisionTreeClassifier(class_weight="balanced", max_depth=4, random_state=42),
}

fig, ax = plt.subplots(figsize=(5, 5))
for name, model in models.items():
    if name == "logistic_regression":
        model.fit(X_train_s, y_train)
        proba = model.predict_proba(X_test_s)[:, 1]
    else:
        model.fit(X_train, y_train)
        proba = model.predict_proba(X_test)[:, 1]

    # Threshold rationale: with severe class imbalance, we optimise for
    # recall (catching compromise) over precision, accepting more analyst
    # triage volume rather than missing a true positive. Threshold chosen
    # at 0.3 rather than the default 0.5 for that reason.
    threshold = 0.3
    preds = (proba >= threshold).astype(int)

    cm = confusion_matrix(y_test, preds).tolist()
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    try:
        auc = roc_auc_score(y_test, proba)
    except ValueError:
        auc = None

    results[name] = {
        "confusion_matrix": cm,
        "precision": round(float(prec), 3),
        "recall": round(float(rec), 3),
        "f1": round(float(f1), 3),
        "roc_auc": round(float(auc), 3) if auc is not None else None,
        "threshold": threshold,
        "n_test": int(len(y_test)),
        "n_positive_test": int(y_test.sum()),
    }

    if auc is not None:
        fpr, tpr, _ = roc_curve(y_test, proba)
        ax.plot(fpr, tpr, label=f"{name} (AUC={auc:.2f})")

ax.plot([0, 1], [0, 1], "k--", alpha=0.4)
ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
ax.set_title("ROC - vendor-session compromise risk models")
ax.legend()
plt.tight_layout()
plt.savefig(f"{FIG}/fig5_roc_curves.png", dpi=110)
plt.close()

# Ranked highest-risk sessions using logistic regression on full dataset
full_scaled = scaler.transform(X)
lr_full = models["logistic_regression"]
data["risk_score"] = lr_full.predict_proba(full_scaled)[:, 1]
top_risk = data.sort_values("risk_score", ascending=False)[
    ["session_id", "vendor_account", "timestamp", "destination_host", "risk_score", "is_compromised_session"]
].head(10)
top_risk.to_csv(f"{OUT}/metrics/top_risk_sessions.csv", index=False)

with open(f"{OUT}/metrics/supervised_model_results.json", "w") as f:
    json.dump({"features_used": FEATURES, "results": results,
               "class_balance": {"positive": int(y.sum()), "negative": int((y==0).sum())}}, f, indent=2)

feat.to_csv(f"{OUT}/vendor_session_features.csv", index=False)

print(json.dumps(results, indent=2))
print("\nTop risk sessions:\n", top_risk.to_string(index=False))
