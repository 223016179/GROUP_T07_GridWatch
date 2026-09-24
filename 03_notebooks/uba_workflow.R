# =====================================================================
# T07 GridWatch — User/Entity Behaviour Analytics (R)
# Session 7 (Access analytics) — R port + atypical-source-IP extension
#
# Part A ports uba.py exactly and validates against the real, already-
# persisted uba_deviation_score column in vendor_session_features.csv -
# this is a correctness check, not guesswork, before anything new is added.
# Part B adds the atypical-source-IP feature flagged as a Session 7 gap
# in the evidence audit (device/location dimension wasn't quantified).
#
# Run: Rscript uba_workflow.R
# Requires: jsonlite (installed automatically below).


if (!requireNamespace("jsonlite", quietly = TRUE)) {
  install.packages("jsonlite", repos = "https://cloud.r-project.org")
}
suppressPackageStartupMessages(library(jsonlite))

set.seed(42)

data <- read.csv("02_data/processed/vendor_session_features.csv", stringsAsFactors = FALSE)
# ground_truth.csv is not merged separately here because is_compromised_session
# is already present in vendor_session_features.csv (it was persisted back into
# this file at the end of the original uba.py run) - merging again would just
# create duplicate columns for no benefit.

# PART A — port of the original uba.py, validated against real output

# A1. Peer-group baselining (ported from acct_profile / KMeans block)

acct_profile <- aggregate(
  cbind(off_hours_flag, session_duration_min, distinct_hosts_48h) ~ vendor_account,
  data = data, FUN = mean
)
names(acct_profile) <- c("vendor_account", "off_hours_rate", "mean_duration", "mean_lateral")

X <- scale(acct_profile[, c("off_hours_rate", "mean_duration", "mean_lateral")])
km <- kmeans(X, centers = 2, nstart = 10)
acct_profile$peer_group <- km$cluster - 1  # R clusters are 1/2; original is 0/1


# A2. Rule-based deviation score (ported exactly from uba.py)

fillna0 <- function(x) ifelse(is.na(x), 0, x)

lateral_z <- (data$distinct_hosts_48h - mean(data$distinct_hosts_48h, na.rm = TRUE)) /
             sd(data$distinct_hosts_48h, na.rm = TRUE)

data$uba_deviation_score_R <- fillna0(abs(data$duration_zscore)) +
                               fillna0(abs(data$hour_zscore)) +
                               fillna0(abs(lateral_z))

# Validation: compare against the real, already-persisted score
diff <- abs(data$uba_deviation_score_R - data$uba_deviation_score)
cat("\n=== PART A VALIDATION: R port vs. real persisted uba_deviation_score ===\n")
cat(sprintf("Max absolute difference across %d sessions: %.6f\n", nrow(data), max(diff, na.rm = TRUE)))
cat(sprintf("Mean absolute difference: %.6f\n", mean(diff, na.rm = TRUE)))
cat(sprintf("Sessions matching to 3 decimal places: %d / %d\n", sum(diff < 0.001, na.rm = TRUE), nrow(data)))

UBA_THRESHOLD_orig_formula <- quantile(data$uba_deviation_score_R, 0.95)
recall_orig_formula <- mean(data$uba_deviation_score_R[data$is_compromised_session == 1] >= UBA_THRESHOLD_orig_formula)
cat(sprintf("Threshold (R, original formula): %.3f  vs. real: 4.118\n", UBA_THRESHOLD_orig_formula))
cat(sprintf("Recall at threshold (R, original formula): %.3f  vs. real: 0.833\n", recall_orig_formula))
cat("==========================================================================\n\n")

# PART B - NEW: atypical-source-IP feature (Session 7 gap closure)

# Design choice, stated explicitly: for each vendor_account, compute how
# often each source_ip is actually used by that account. A session from
# an IP the account rarely uses is scored as more "atypical." This
# operationalises the source-IP anomaly that was previously only
# referenced qualitatively (the case's "off_hours_or_atypical_ip"
# evidence item), without altering any existing feature or score.

ip_usage <- aggregate(session_id ~ vendor_account + source_ip, data = data, FUN = length)
names(ip_usage)[3] <- "ip_session_count"
acct_totals <- aggregate(session_id ~ vendor_account, data = data, FUN = length)
names(acct_totals)[2] <- "acct_total_sessions"
ip_usage <- merge(ip_usage, acct_totals, by = "vendor_account")
ip_usage$ip_usage_fraction <- ip_usage$ip_session_count / ip_usage$acct_total_sessions

data <- merge(data, ip_usage[, c("vendor_account", "source_ip", "ip_usage_fraction")],
              by = c("vendor_account", "source_ip"), all.x = TRUE)

# atypical_ip_score: 0 = account's usual IP, approaching 1 = rarely-used IP
data$atypical_ip_score <- 1 - data$ip_usage_fraction
# binary flag for interpretability: IP used in < 10% of this account's sessions
data$atypical_ip_flag <- as.integer(data$ip_usage_fraction < 0.10)

# Scaled to sit on a comparable magnitude to the existing abs-z-score terms
# (which typically range ~0-4). A factor of 3 means an always-rare IP
# contributes roughly as much as a 3-sigma deviation on the existing terms -
# a deliberate, stated weighting choice, not a fitted one.
IP_SCALE_FACTOR <- 3
data$uba_deviation_score_v2 <- data$uba_deviation_score_R + data$atypical_ip_score * IP_SCALE_FACTOR

UBA_THRESHOLD_v2 <- quantile(data$uba_deviation_score_v2, 0.95)
data$uba_flagged_v2 <- as.integer(data$uba_deviation_score_v2 >= UBA_THRESHOLD_v2)
recall_v2 <- mean(data$uba_flagged_v2[data$is_compromised_session == 1] == 1)
sessions_flagged_v2 <- sum(data$uba_flagged_v2)

cat("=== PART B: with atypical-source-IP feature added ===\n")
cat(sprintf("New threshold (95th pct, score + IP term): %.3f\n", UBA_THRESHOLD_v2))
cat(sprintf("Sessions flagged: %d  (original: 17)\n", sessions_flagged_v2))
cat(sprintf("Recall of injected compromise: %.3f  (original: 0.833)\n", recall_v2))

# Which specific sessions change status vs. the original flagging
data$uba_flagged_orig <- as.integer(data$uba_deviation_score_R >= UBA_THRESHOLD_orig_formula)
newly_flagged <- data[data$uba_flagged_v2 == 1 & data$uba_flagged_orig == 0, ]
no_longer_flagged <- data[data$uba_flagged_v2 == 0 & data$uba_flagged_orig == 1, ]
cat(sprintf("Sessions newly flagged by adding the IP feature: %d\n", nrow(newly_flagged)))
cat(sprintf("Sessions no longer flagged (displaced by the new threshold): %d\n", nrow(no_longer_flagged)))
if (nrow(newly_flagged) > 0) {
  cat("Newly flagged sessions (session_id, vendor_account, is_compromised_session):\n")
  print(newly_flagged[order(-newly_flagged$uba_deviation_score_v2),
                       c("session_id", "vendor_account", "is_compromised_session")])
}
cat("======================================================\n\n")


# Top anomalies (v2) and figure

flagged_v2 <- data[data$uba_flagged_v2 == 1, ]
flagged_v2 <- flagged_v2[order(-flagged_v2$uba_deviation_score_v2), ]
top_anomalies_v2 <- head(flagged_v2[, c("session_id", "vendor_account", "timestamp", "destination_host",
                                         "uba_deviation_score_v2", "atypical_ip_flag", "is_compromised_session")], 15)

out_dir <- "04_models"
if (!dir.exists(out_dir)) dir.create(out_dir, recursive = TRUE)
write.csv(top_anomalies_v2, file.path(out_dir, "uba_top_anomalies_with_ip_R.csv"), row.names = FALSE)

fig_dir <- "04_models/figures"
if (!dir.exists(fig_dir)) dir.create(fig_dir, recursive = TRUE)
png(file.path(fig_dir, "fig6_uba_deviation_distribution_v2_R.png"), width = 800, height = 400, res = 110)
normal <- data$uba_deviation_score_v2[data$is_compromised_session == 0]
compromised <- data$uba_deviation_score_v2[data$is_compromised_session == 1]
hist(normal, breaks = 30, col = rgb(0.3, 0.5, 0.8, 0.6), border = NA,
     xlab = "UBA deviation score (with atypical-IP term)", ylab = "session count",
     main = "UBA deviation-score distribution (v2) vs. 95th-percentile threshold",
     xlim = range(c(normal, compromised)))
hist(compromised, breaks = 10, col = rgb(0.85, 0.2, 0.2, 0.8), border = NA, add = TRUE)
abline(v = UBA_THRESHOLD_v2, col = "black", lty = 2)
legend("topright", legend = c("normal sessions", "injected compromise sessions",
                               sprintf("95th pct threshold=%.2f", UBA_THRESHOLD_v2)),
       fill = c(rgb(0.3, 0.5, 0.8, 0.6), rgb(0.85, 0.2, 0.2, 0.8), NA),
       border = NA, lty = c(NA, NA, 2), bty = "n", cex = 0.8)
dev.off()

# Export

output <- list(
  part_a_validation = list(
    max_abs_diff_vs_real_score = round(max(diff, na.rm = TRUE), 6),
    threshold_R = round(as.numeric(UBA_THRESHOLD_orig_formula), 3),
    threshold_real = 4.118,
    recall_R = round(recall_orig_formula, 3),
    recall_real = 0.833
  ),
  part_b_with_atypical_ip = list(
    feature_definition = "atypical_ip_score = 1 - (sessions from this exact source_ip for this account / total sessions for this account); scaled by 3x and added to the existing deviation score",
    threshold_v2 = round(as.numeric(UBA_THRESHOLD_v2), 3),
    sessions_flagged_v2 = sessions_flagged_v2,
    recall_v2 = round(recall_v2, 3),
    newly_flagged_count = nrow(newly_flagged),
    no_longer_flagged_count = nrow(no_longer_flagged)
  ),
  peer_groups = acct_profile
)

write_json(output, "04_models/uba_results_with_ip_R.json", auto_unbox = TRUE, pretty = TRUE)
cat("Results written to 04_models/uba_results_with_ip_R.json\n")
cat("Top anomalies written to 04_models/uba_top_anomalies_with_ip_R.csv\n")
cat("Figure written to 04_models/figures/fig6_uba_deviation_distribution_v2_R.png\n")