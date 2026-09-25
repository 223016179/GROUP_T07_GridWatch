
# T07 GridWatch - Adversarial Robustness: Decision Tree Extension (R)
# Session 10 (Advanced security intelligence) — closing the gap flagged in the evidence audit: adversarial testing had only been run against the logistic regression scoring engine, not the decision tree.
##
# Design notes (read before trusting the numbers):
#  - The base-case session (the single highest-scoring known-compromised session) is selected using the REAL, already-persisted predictive_risk_score column in vendor_session_features.csv - this is your actual LR's output, not an R re-fit or approximation, so the base case is guaranteed identical to the one in predictive_adversarial_results.json.
#  - The three adversarial perturbations are copied EXACTLY from predictive_adversarial.py (same features, same changed values).
#  - The decision tree itself is trained on the FULL dataset, not the 70/30 split used in supervised_model.py. This follows the same precedent your own predictive_adversarial.py already set for the  logistic regression (it also refits on full data rather than reusing the split model) - chosen specifically because sklearn' train_test_split(random_state=42) cannot be reproduced row-for-row in R (different RNG algorithm entirely), so matching Python's split  isn't achievable even in principle. Consistent methodology beats a false claim of exact replication.
##

if (!requireNamespace("jsonlite", quietly = TRUE)) {
  install.packages("jsonlite", repos = "https://cloud.r-project.org")
}
suppressPackageStartupMessages({
  library(rpart)
  library(jsonlite)
})

set.seed(07)

data <- read.csv("02_data/processed/vendor_session_features.csv", stringsAsFactors = FALSE)

FEATURES <- c("off_hours_flag", "hour_zscore", "duration_zscore", "failed_logon",
              "distinct_hosts_48h", "edr_alerts_near", "edr_high_crit_near")

for (f in FEATURES) data[[f]][is.na(data[[f]])] <- 0  # fillna(0), matches Python


## 1. TRAIN DECISION TREE ON FULL DATA (balanced weights, max depth 4)

y <- data$is_compromised_session
n <- length(y)
n_pos <- sum(y == 1); n_neg <- sum(y == 0)
# sklearn class_weight="balanced": w_i = n_samples / (n_classes * count[class])
case_weights <- ifelse(y == 1, n / (2 * n_pos), n / (2 * n_neg))

form <- as.formula(paste("as.factor(is_compromised_session) ~", paste(FEATURES, collapse = " + ")))
tree_model <- rpart(
  form, data = data, weights = case_weights, method = "class",
  control = rpart.control(maxdepth = 4, cp = 0, minsplit = 2, minbucket = 1)
)

# Internal consistency check (NOT a held-out validation, since this tree
# is trained on full data, unlike Session 3's split-evaluated tree):
tree_proba_all <- predict(tree_model, data, type = "prob")[, "1"]
cat("=== Full-data decision tree: internal check ===\n")
cat(sprintf("Mean predicted P(compromise) for the %d known-compromised sessions: %.3f\n",
            n_pos, mean(tree_proba_all[y == 1])))
cat(sprintf("Mean predicted P(compromise) for the %d normal sessions: %.3f\n",
            n_neg, mean(tree_proba_all[y == 0])))
cat("(This is a full-data fit, not a held-out test - unlike the 0.5 AUC test-set\n")
cat(" result already on file for Session 3's split-trained tree. Not directly comparable.)\n\n")

#
## 2. SELECT THE SAME BASE CASE AS THE REAL LR ADVERSARIAL TEST

compromised <- data[data$is_compromised_session == 1, ]
base_row <- compromised[which.max(compromised$predictive_risk_score), ]
cat(sprintf("Base case session: %s (vendor_account: %s), real LR predictive_risk_score: %.3f\n\n",
            base_row$session_id, base_row$vendor_account, base_row$predictive_risk_score))

base_features <- as.list(base_row[FEATURES])


# 3. SCORING FUNCTION FOR THE TREE (no scaling needed - trees are scale-invariant)

score_tree <- function(features_list) {
  newdata <- as.data.frame(features_list, stringsAsFactors = FALSE)
  as.numeric(predict(tree_model, newdata, type = "prob")[, "1"])
}

base_score_tree <- score_tree(base_features)

## 4. THE SAME 3 ADVERSARIAL CASES, COPIED EXACTLY FROM predictive_adversarial.py

apply_changes <- function(base, changes) {
  out <- base
  for (nm in names(changes)) out[[nm]] <- changes[[nm]]
  out
}

c1_features <- apply_changes(base_features, list(edr_alerts_near = 0, edr_high_crit_near = 0))
c2_features <- apply_changes(base_features, list(edr_alerts_near = 0, edr_high_crit_near = 0,
                                                  off_hours_flag = 0, hour_zscore = 0.2,
                                                  duration_zscore = 0.1))
c3_features <- apply_changes(base_features, list(edr_alerts_near = 0, edr_high_crit_near = 0,
                                                  off_hours_flag = 0, hour_zscore = 0.2,
                                                  duration_zscore = 0.1, distinct_hosts_48h = 1))

ALERT_THRESHOLD <- 0.5

c1_score <- score_tree(c1_features)
c2_score <- score_tree(c2_features)
c3_score <- score_tree(c3_features)

adversarial_cases_tree <- list(
  list(case = "Living-off-the-land tooling (avoids known-bad EDR signatures)",
       original_score = round(base_score_tree, 3), evasion_score = round(c1_score, 3),
       evaded_at_alert_threshold = c1_score < ALERT_THRESHOLD),
  list(case = "Living-off-the-land + timing/duration mimicry",
       original_score = round(base_score_tree, 3), evasion_score = round(c2_score, 3),
       evaded_at_alert_threshold = c2_score < ALERT_THRESHOLD),
  list(case = "Full behavioural mimicry: LOTL tooling + timing + duration + single-host reach",
       original_score = round(base_score_tree, 3), evasion_score = round(c3_score, 3),
       evaded_at_alert_threshold = c3_score < ALERT_THRESHOLD)
)

n_evaded_tree <- sum(vapply(adversarial_cases_tree, function(c) c$evaded_at_alert_threshold, logical(1)))


# 5. SIDE-BY-SIDE COMPARISON WITH THE REAL LOGISTIC REGRESSION RESULTS

# Hardcoded from predictive_adversarial_results.json (the real LR results)
lr_results <- list(
  list(case = "LOTL tooling", original_score = 1.0, evasion_score = 1.0, evaded = FALSE),
  list(case = "LOTL + timing/duration mimicry", original_score = 1.0, evasion_score = 0.539, evaded = FALSE),
  list(case = "Full behavioural mimicry", original_score = 1.0, evasion_score = 0.003, evaded = TRUE)
)

cat("=== Decision tree adversarial results ===\n")
cat(sprintf("%-70s %9s %9s %8s\n", "Case", "Orig", "Evasion", "Evaded?"))
for (c in adversarial_cases_tree) {
  cat(sprintf("%-70s %9.3f %9.3f %8s\n", c$case, c$original_score, c$evasion_score,
              ifelse(c$evaded_at_alert_threshold, "YES", "no")))
}
cat(sprintf("\nDecision tree: %d of 3 cases evade detection\n", n_evaded_tree))
cat("Logistic regression (real, on file): 1 of 3 cases evade detection\n\n")

# 6. EXPORT

output <- list(
  note = "Extends the real predictive_adversarial_results.json (logistic regression) with the same base case and same 3 perturbations tested against a decision tree",
  base_case_session = base_row$session_id,
  base_case_real_lr_score = round(base_row$predictive_risk_score, 3),
  methodology_note = "Decision tree trained on the FULL dataset (not the 70/30 split), for consistency with how predictive_adversarial.py already refits the logistic regression on full data rather than reusing the split model - sklearn's exact train_test_split row assignment cannot be reproduced in R regardless of matching random seeds, since R and Python use different RNG algorithms",
  decision_tree_adversarial_cases = adversarial_cases_tree,
  decision_tree_n_evaded = sprintf("%d/3", n_evaded_tree),
  logistic_regression_comparison = lr_results,
  logistic_regression_n_evaded = "1/3 (from predictive_adversarial_results.json)"
)

write_json(output, "predictive_adversarial_results_with_tree_R.json", auto_unbox = TRUE, pretty = TRUE)
cat("Results written to predictive_adversarial_results_with_tree_R.json\n")