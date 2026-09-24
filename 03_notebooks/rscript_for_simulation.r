# SIMULATION WORKFLOW
# GRAPH DEFINITION
JUMP       <- "JUMP-OT-01"
ENG_HOSTS  <- sprintf("ENG-WKS-%02d", 1:5)
HISTORIAN  <- "HIST-SRV-01"
PLCS       <- sprintf("PLC-%02d", 1:6)
RTUS       <- sprintf("RTU-%02d", 1:8)
node_kind <- c(
setNames("jump_host", JUMP),
setNames(rep("engineering_workstation", length(ENG_HOSTS)), ENG_HOSTS),
setNames("historian", HISTORIAN),
setNames(rep("plc", length(PLCS)), PLCS),
setNames(rep("rtu", length(RTUS)), RTUS)
)
all_nodes <- names(node_kind)
edges <- data.frame(from = character(0), to = character(0), stringsAsFactors = FALSE)
add_edge <- function(a, b) edges[nrow(edges) + 1, ] <<- c(a, b)
for (h in ENG_HOSTS) add_edge(JUMP, h)          # 5 edges
add_edge(JUMP, HISTORIAN)                        # 1 edge
for (i in seq_along(PLCS)) {                     # 6 edges
add_edge(ENG_HOSTS[((i - 1) %% length(ENG_HOSTS)) + 1], PLCS[i])
}
for (i in seq_along(RTUS)) {                     # 8 edges
add_edge(PLCS[((i - 1) %% length(PLCS)) + 1], RTUS[i])
if ((i - 1) %% 3 == 0) add_edge(HISTORIAN, RTUS[i])  # +3 extra edges (i=1,4,7 in 1-indexed)
}
stopifnot(length(all_nodes) == 21, nrow(edges) == 23)
adj <- setNames(vector("list", length(all_nodes)), all_nodes)
for (n in all_nodes) adj[[n]] <- character(0)
for (i in seq_len(nrow(edges))) {
a <- edges$from[i]; b <- edges$to[i]
adj[[a]] <- c(adj[[a]], b)
adj[[b]] <- c(adj[[b]], a)
}
ENTRY_POINT <- JUMP
View(edges)
# 2. SINGLE-RUN PROPAGATION
simulate_propagation_once <- function(entry, base_p = 0.55, max_hops = 4,
segmented_nodes = character(0),
mfa_dampening = 1.0) {
reached  <- entry
frontier <- entry
for (hop in seq_len(max_hops)) {
new_frontier <- character(0)
for (node in frontier) {
for (neighbor in adj[[node]]) {
if (neighbor %in% reached || neighbor %in% segmented_nodes) next
p <- base_p * mfa_dampening
if (runif(1) < p) {
reached <- c(reached, neighbor)
new_frontier <- c(new_frontier, neighbor)
}
}
}
frontier <- unique(new_frontier)
if (length(frontier) == 0) break
}
reached <- unique(reached)
list(blast_radius = length(reached) - 1, reached = reached)  # exclude entry itself
}
simulate_propagation <- function(entry, n_iterations, base_p = 0.55, max_hops = 4,
segmented_nodes = character(0), mfa_dampening = 1.0) {
# NOTE: deliberately NOT using replicate(n, f(x, ...)) here - replicate()
# wraps its expression in its own function(...) internally, which shadows
# any ... you try to forward through it, so named args silently vanish.
# lapply with explicit named arguments avoids that trap.
lapply(seq_len(n_iterations), function(i) {
simulate_propagation_once(entry, base_p = base_p, max_hops = max_hops,
segmented_nodes = segmented_nodes, mfa_dampening = mfa_dampening)
})
}
# 3. SCENARIOS
n_iterations <- 1000  # upgraded from the original 200 (charter's recommended minimum)
# segmentation isolates every 3rd RTU (0-indexed i %% 3 == 0 in Python ->
# RTU-01, RTU-04, RTU-07 in 1-indexed R)
segmented_nodes <- RTUS[seq(1, length(RTUS), by = 3)]
baseline              <- simulate_propagation(ENTRY_POINT, n_iterations, base_p = 0.55, max_hops = 4)
control_segmentation  <- simulate_propagation(ENTRY_POINT, n_iterations, base_p = 0.55, max_hops = 4,
segmented_nodes = segmented_nodes)
control_mfa           <- simulate_propagation(ENTRY_POINT, n_iterations, base_p = 0.55, max_hops = 4,
mfa_dampening = 0.4)
control_combined      <- simulate_propagation(ENTRY_POINT, n_iterations, base_p = 0.55, max_hops = 4,
segmented_nodes = segmented_nodes, mfa_dampening = 0.4)
scenarios <- list(
baseline_no_controls  = baseline,
network_segmentation  = control_segmentation,
vendor_mfa            = control_mfa,
segmentation_plus_mfa = control_combined
)
# 4. SUMMARISE
ot_node_types <- c("plc", "rtu")
summarise_scenario <- function(runs) {
blast_radii <- vapply(runs, function(r) r$blast_radius, numeric(1))
# original definition: did compromise spread past the entry point at all
reached_any <- blast_radii >= 1
# stricter definition: did compromise reach an actual PLC/RTU node
reached_ot_strict <- vapply(runs, function(r) {
kinds <- node_kind[r$reached]
any(kinds %in% ot_node_types)
}, logical(1))
list(
mean_blast_radius = round(mean(blast_radii), 2),
p90_blast_radius = round(as.numeric(quantile(blast_radii, 0.9)), 2),
max_blast_radius = max(blast_radii),
pct_reaching_any_ot_asset = round(mean(reached_any), 3),               # matches original definition
pct_reaching_ot_asset_strict = round(mean(reached_ot_strict), 3)       # supplementary, node-type-checked
)
}
summary_list <- lapply(scenarios, summarise_scenario)
View(summary_list)
summary_list[["baseline_no_controls"]]
summary_list[["network_segmentation"]]
summary_list[["vendor_mfa"]]
summary_list[["segmentation_plus_mfa"]]
# 5. CONSOLE SUMMARY
cat("\n------------------ SIMULATION SUMMARY (R port,", n_iterations, "iterations/scenario) ------------\n")
cat(sprintf("%-24s %9s %8s %8s %14s %16s\n",
"Scenario", "Mean BR", "P90 BR", "Max BR", "%any(orig)", "%OT(strict)"))
for (nm in names(summary_list)) {
s <- summary_list[[nm]]
cat(sprintf("%-24s %9.2f %8.2f %8d %13.1f%% %15.1f%%\n",
nm, s$mean_blast_radius, s$p90_blast_radius, s$max_blast_radius,
s$pct_reaching_any_ot_asset * 100, s$pct_reaching_ot_asset_strict * 100))
}
cat("--------------------------------------------------------------------------------------------------\n\n")
cat("Comparison to original 200-iteration Python run (simulation_results.json):\n")
cat("  baseline_no_controls   mean BR 8.03 (Python) vs", summary_list$baseline_no_controls$mean_blast_radius, "(R)\n")
cat("  vendor_mfa              mean BR 2.01 (Python) vs", summary_list$vendor_mfa$mean_blast_radius, "(R)\n")
cat("  (small differences vs. Python are expected - different RNG stream, same graph/rules/iteration count upgrade)\n\n")
# 6. HISTOGRAM
fig_dir <- "05_simulation/figures"
if (!dir.exists(fig_dir)) dir.create(fig_dir, recursive = TRUE)
cols <- c(baseline_no_controls = rgb(0.30, 0.55, 0.85, 0.5),
network_segmentation = rgb(0.95, 0.65, 0.25, 0.5),
vendor_mfa            = rgb(0.35, 0.75, 0.35, 0.5),
segmentation_plus_mfa = rgb(0.85, 0.35, 0.35, 0.5))
max_br <- max(vapply(scenarios, function(s) max(vapply(s, function(r) r$blast_radius, numeric(1))), numeric(1)))
breaks <- seq(0, max_br + 1, by = 1)
png(file.path(fig_dir, "fig7_propagation_simulation_R.png"), width = 900, height = 500, res = 110)
par(mar = c(4, 4, 3, 1))
plot(NULL, xlim = c(0, max_br + 1), ylim = c(0, n_iterations * 0.4),
xlab = "Blast radius (# assets reached from entry point)",
ylab = sprintf("Simulation runs (of %d)", n_iterations),
main = "Propagation simulation: baseline vs. alternative controls (R port)")
for (nm in names(scenarios)) {
br <- vapply(scenarios[[nm]], function(r) r$blast_radius, numeric(1))
h <- hist(br, breaks = breaks, plot = FALSE)
rect(h$breaks[-length(h$breaks)], 0, h$breaks[-1], h$counts, col = cols[nm], border = NA)
}
legend("topright", legend = names(scenarios), fill = cols, cex = 0.7, bty = "n")
dev.off()
cat(sprintf("Histogram written to %s\n", file.path(fig_dir, "fig7_propagation_simulation_R.png")))
# 7. EXPORT (mirrors simulation_results.json, plus the strict OT field)
output <- list(
model = sprintf("Monte Carlo hop-based propagation over synthetic OT/engineering graph (%d nodes, %d edges) - R port",
length(all_nodes), nrow(edges)),
assumptions = list(
"Spread probability per hop is uniform (0.55) absent controls - a simplification",
"Segmentation fully blocks spread into named nodes (RTU-01/04/07); MFA reduces (not eliminates) spread probability by 60%",
"4-hop cap approximates the case investigation window's dwell time",
sprintf("%d Monte Carlo iterations per scenario to characterise uncertainty (upgraded from the original 200)", n_iterations),
"pct_reaching_any_ot_asset replicates the original metric definition (blast radius >= 1, i.e. spread past the entry point at all); pct_reaching_ot_asset_strict is a supplementary node-type-checked measure of specifically reaching a PLC/RTU"
),
iterations = n_iterations,
scenario_results = summary_list
)
View(summary_list)
View(scenarios)
out_dir <- "05_simulation"
out_path <- file.path(out_dir, "simulation_results_R.json")
write_json(output, out_path, auto_unbox = TRUE, pretty = TRUE)
cat(sprintf("Results written to %s\n", out_path))
