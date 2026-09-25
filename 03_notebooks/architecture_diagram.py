import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

FIG = "/home/claude/gridwatch/outputs/figures"

fig, ax = plt.subplots(figsize=(11, 7))
ax.set_xlim(0, 11)
ax.set_ylim(0, 9)
ax.axis("off")

IMPLEMENTED = "#4fae82"
PLANNED = "#8a97a3"
DEFERRED = "#c96a6a"

def box(x, y, w, h, label, status):
    color = {"implemented": IMPLEMENTED, "planned": PLANNED, "deferred": DEFERRED}[status]
    style = "-" if status != "deferred" else "--"
    b = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08",
                        linewidth=1.8, edgecolor=color, facecolor="white",
                        linestyle=style)
    ax.add_patch(b)
    ax.text(x + w/2, y + h/2, label, ha="center", va="center", fontsize=8.5, wrap=True)

def arrow(x1, y1, x2, y2):
    a = FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12,
                         color="#444", linewidth=1.2)
    ax.add_patch(a)

# Data sources row
box(0.3, 7.5, 2.0, 1.0, "Vendor auth log\n(synthetic, 323 rows)", "implemented")
box(2.6, 7.5, 2.0, 1.0, "EDR telemetry\n(synthetic, 590 rows)", "implemented")
box(4.9, 7.5, 2.0, 1.0, "OT IDS/historian\n(synthetic, 1580 rows)", "implemented")
box(7.2, 7.5, 2.0, 1.0, "Threat-intel corpus\n(20 of 15-30 target docs)", "implemented")

arrow(1.3, 7.5, 1.3, 6.6)
arrow(3.6, 7.5, 3.6, 6.6)
arrow(5.9, 7.5, 5.9, 6.6)
arrow(8.2, 7.5, 8.2, 6.6)

box(0.3, 5.6, 8.9, 1.0, "Prepare & correlate: cleaning, feature engineering, session-level join (feature store: vendor_session_features.csv)", "implemented")

arrow(4.75, 5.6, 4.75, 4.7)

box(0.3, 3.6, 2.0, 1.0, "Supervised ML\n(logistic reg. + tree)", "implemented")
box(2.6, 3.6, 2.0, 1.0, "UBA / anomaly\nbaselining", "implemented")
box(4.9, 3.6, 2.0, 1.0, "IT/OT timeline\ncorrelation", "implemented")
box(7.2, 3.6, 1.0, 1.0, "Text\nmining", "implemented")
box(8.35, 3.6, 0.85, 1.0, "Propag.\nsim", "implemented")

arrow(1.3, 3.6, 3.5, 2.7)
arrow(3.6, 3.6, 3.9, 2.7)
arrow(5.9, 3.6, 4.5, 2.7)
arrow(7.7, 3.6, 5.0, 2.7)
arrow(8.8, 3.6, 5.3, 2.7)

box(1.2, 1.8, 6.5, 0.9, "Predictive/adversarial risk scoring + governance", "implemented")
arrow(4.45, 1.8, 4.45, 1.0)

box(0.9, 0.1, 7.1, 0.9, "Dashboard prototype: risk console (8 pages, HTML/JS, tested)", "implemented")

box(8.4, 1.8, 2.2, 0.9, "SOC ticketing\nintegration", "deferred")
box(8.4, 0.4, 2.2, 0.9, "Live vendor/\nutility feed", "deferred")

legend_handles = [
    mpatches.Patch(edgecolor=IMPLEMENTED, facecolor="white", label="Implemented (this milestone)"),
    mpatches.Patch(edgecolor=PLANNED, facecolor="white", label="Planned (in progress)"),
    mpatches.Patch(edgecolor=DEFERRED, facecolor="white", linestyle="--", label="Deferred (out of scope / future work)"),
]
ax.legend(handles=legend_handles, loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=3, fontsize=8, frameon=False)

ax.set_title("GridWatch — implemented architecture and data flow (Milestone 2)", fontsize=12, fontweight="bold")
plt.tight_layout()
plt.savefig(f"{FIG}/fig0_architecture.png", dpi=130, bbox_inches="tight")
plt.close()
print("saved architecture diagram")
