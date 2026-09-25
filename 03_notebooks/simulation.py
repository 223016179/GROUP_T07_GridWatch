import networkx as nx
import numpy as np
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = "/home/claude/gridwatch/outputs"
FIG = f"{OUT}/figures"
rng = np.random.default_rng(42)

# ----------------------------------------------------------------------
# Build a representative OT/engineering network graph consistent with the
# case's asset inventory (Section 6/7 of charter). This is a simplified,
# synthetic topology for simulation purposes only - not a real network map.
# ----------------------------------------------------------------------
G = nx.Graph()
JUMP = "JUMP-OT-01"
ENG_HOSTS = [f"ENG-WKS-{n:02d}" for n in range(1, 6)]
HISTORIAN = "HIST-SRV-01"
PLCS = [f"PLC-{n:02d}" for n in range(1, 7)]
RTUS = [f"RTU-{n:02d}" for n in range(1, 9)]

G.add_node(JUMP, kind="jump_host")
for h in ENG_HOSTS:
    G.add_node(h, kind="engineering_workstation")
    G.add_edge(JUMP, h)
G.add_node(HISTORIAN, kind="historian")
G.add_edge(JUMP, HISTORIAN)
for i, plc in enumerate(PLCS):
    G.add_node(plc, kind="plc")
    G.add_edge(ENG_HOSTS[i % len(ENG_HOSTS)], plc)
for i, rtu in enumerate(RTUS):
    G.add_node(rtu, kind="rtu")
    G.add_edge(PLCS[i % len(PLCS)], rtu)
    if i % 3 == 0:
        G.add_edge(HISTORIAN, rtu)  # some RTUs also historian-connected

ENTRY_POINT = JUMP

def simulate_propagation(graph, entry, controls=None, n_iterations=200):
    """Monte Carlo propagation: at each hop, compromise spreads to a
    neighbouring asset with probability p (reduced by controls in place).
    Returns distribution of 'blast radius' (# assets reached) across
    iterations, to capture uncertainty rather than a single point estimate."""
    controls = controls or {}
    base_p = controls.get("base_spread_prob", 0.55)
    max_hops = controls.get("max_hops", 4)
    segmentation_block = set(controls.get("segmented_nodes", []))  # nodes spread cannot cross into

    blast_radii = []
    for _ in range(n_iterations):
        reached = {entry}
        frontier = {entry}
        for hop in range(max_hops):
            new_frontier = set()
            for node in frontier:
                for neighbor in graph.neighbors(node):
                    if neighbor in reached or neighbor in segmentation_block:
                        continue
                    p = base_p * (controls.get("mfa_dampening", 1.0))
                    if rng.random() < p:
                        reached.add(neighbor)
                        new_frontier.add(neighbor)
            frontier = new_frontier
            if not frontier:
                break
        blast_radii.append(len(reached) - 1)  # exclude entry point itself
    return blast_radii

# --- Baseline scenario: current controls (none of the two below) ---
baseline = simulate_propagation(G, ENTRY_POINT, controls={"base_spread_prob": 0.55, "max_hops": 4})

# --- Alternative control 1: network segmentation isolating historian-linked RTUs ---
segmented_nodes = [rtu for i, rtu in enumerate(RTUS) if i % 3 == 0]
control_segmentation = simulate_propagation(
    G, ENTRY_POINT,
    controls={"base_spread_prob": 0.55, "max_hops": 4, "segmented_nodes": segmented_nodes},
)

# --- Alternative control 2: MFA on vendor remote access, dampening spread probability ---
control_mfa = simulate_propagation(
    G, ENTRY_POINT,
    controls={"base_spread_prob": 0.55, "max_hops": 4, "mfa_dampening": 0.4},
)

# --- Combined controls ---
control_combined = simulate_propagation(
    G, ENTRY_POINT,
    controls={"base_spread_prob": 0.55, "max_hops": 4,
              "segmented_nodes": segmented_nodes, "mfa_dampening": 0.4},
)

scenarios = {
    "baseline_no_controls": baseline,
    "network_segmentation": control_segmentation,
    "vendor_mfa": control_mfa,
    "segmentation_plus_mfa": control_combined,
}

summary = {}
for name, radii in scenarios.items():
    summary[name] = {
        "mean_blast_radius": round(float(np.mean(radii)), 2),
        "p90_blast_radius": round(float(np.percentile(radii, 90)), 2),
        "max_blast_radius": int(np.max(radii)),
        "pct_reaching_any_ot_asset": round(float(np.mean(np.array(radii) >= 1)), 3),
    }

# --- Plot comparison ---
fig, ax = plt.subplots(figsize=(9, 5))
for name, radii in scenarios.items():
    ax.hist(radii, bins=range(0, max(max(r) for r in scenarios.values()) + 2),
            alpha=0.5, label=name)
ax.set_xlabel("Blast radius (# assets reached from entry point)")
ax.set_ylabel("Simulation runs (of 200)")
ax.set_title("Propagation simulation: baseline vs. alternative controls")
ax.legend(fontsize=8)
plt.tight_layout()
plt.savefig(f"{FIG}/fig7_propagation_simulation.png", dpi=110)
plt.close()

# --- Network diagram highlighting compromised-reachable assets (baseline, single illustrative run) ---
illustrative_reached = {ENTRY_POINT}
frontier = {ENTRY_POINT}
for _ in range(4):
    new_frontier = set()
    for node in frontier:
        for neighbor in G.neighbors(node):
            if neighbor not in illustrative_reached and rng.random() < 0.55:
                illustrative_reached.add(neighbor)
                new_frontier.add(neighbor)
    frontier = new_frontier

pos = nx.spring_layout(G, seed=42)
fig, ax = plt.subplots(figsize=(9, 7))
node_colors = ["red" if n in illustrative_reached else "lightgray" for n in G.nodes()]
nx.draw(G, pos, ax=ax, node_color=node_colors, with_labels=True, font_size=7, node_size=500, edge_color="gray")
ax.set_title("Illustrative blast radius from compromised vendor entry point (single run)")
plt.tight_layout()
plt.savefig(f"{FIG}/fig8_network_blast_radius.png", dpi=110)
plt.close()

result = {
    "model": "Monte Carlo hop-based propagation over synthetic OT/engineering graph "
             f"({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)",
    "assumptions": [
        "Spread probability per hop is uniform (0.55) absent controls - a simplification",
        "Segmentation fully blocks spread into named nodes; MFA reduces (not eliminates) spread probability by 60%",
        "4-hop cap approximates the case investigation window's dwell time",
        "200 Monte Carlo iterations per scenario to characterise uncertainty",
    ],
    "iterations": 200,
    "scenario_results": summary,
}

with open(f"{OUT}/metrics/simulation_results.json", "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
