"""Generate all evaluation figures (PDF) and print the numbers used in the tables."""
import json
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"pdf.fonttype": 42, "ps.fonttype": 42, "font.size": 9,
                     "axes.titlesize": 9, "legend.fontsize": 7.5, "axes.grid": True,
                     "grid.alpha": 0.3, "figure.dpi": 150})
OUT = os.environ.get("FIGDIR", "../../figs")
os.makedirs(OUT, exist_ok=True)
R = "results/"
costs = json.load(open(R + "costs.json"))
sim = json.load(open(R + "sim.json"))
srv = json.load(open(R + "server.json"))
PLAT = ["Laptop", "RPi 5", "Galaxy A07"]
POWER = [15.0, 5.0, 3.0]
COL = ["#0072B2", "#E69F00", "#009E73", "#CC79A7", "#56B4E9", "#D55E00", "#000000", "#999999", "#F0E442"]

# --- Table 4 (authors' testbed), ms
PRIM = [("Hash", "H", (0.025, 0.042, 0.038)), ("HMAC-SHA-256", "HMAC", (0.031, 0.052, 0.047)),
        ("PUF", "PUF", (0.220, 0.380, 0.350)), ("ECC point mult.", "ECC", (3.297, 5.480, 5.120)),
        ("ECC point add.", "EA", (0.085, 0.140, 0.130)), ("Sym. enc./dec.", "SED", (0.016, 0.028, 0.025)),
        ("Chebyshev map", "CH", (0.210, 0.360, 0.330)), ("Bilinear pairing", "BP", (5.400, 9.100, 8.500)),
        ("Fuzzy extractor", "FE", (0.850, 1.420, 1.330)), ("Schnorr verify", "SV", (0.160, 0.270, 0.250)),
        ("IPFS operation", "IPFS", (0.500, 0.840, 0.780)), ("XOR", "XOR", (0.001, 0.002, 0.002))]
T = {sym: v for _, sym, v in PRIM}
summary = {"prim": []}
for name, sym, v in PRIM:
    summary["prim"].append((name, sym, v, float(np.mean(v)), float(np.std(v))))


def cost(ops):
    return [sum(n * T[s][i] for s, n in ops.items()) for i in range(3)]


oc = costs["op_counts"]
SCHEMES = [
    ("SPUFChain", {"H": 20, "PUF": 4}, False),
    ("TS-PAID", {"H": 16, "CH": 7, "SED": 6}, False),
    ("Gai et al.", {"BP": 3, "H": 32}, False),
    ("Sun et al.*", {"H": 8, "IPFS": 1, "SV": 1}, True),
    ("Wang et al.*", {"H": 6, "SED": 3}, True),
    ("Static-key baseline", {"HMAC": 24, "XOR": 8}, False),
    ("LSACP delegation", {"HMAC": oc["delegation"]["total"]["hmac"], "XOR": oc["delegation"]["total"]["xor"]}, False),
    ("LSACP delegation (tag)", {"HMAC": oc["delegation"]["ET"]["hmac"], "XOR": oc["delegation"]["ET"]["xor"]}, False),
    ("LSACP access", {"HMAC": oc["access"]["total"]["hmac"]}, False),
    ("LSACP revocation", {"HMAC": oc["revocation"]["total"]["hmac"], "XOR": oc["revocation"]["total"]["xor"]}, False),
]
summary["comp"] = []
for name, ops, lb in SCHEMES:
    c = cost(ops)
    e = [c[i] * POWER[i] for i in range(3)]
    summary["comp"].append((name, c, float(np.mean(c)), e, float(np.mean(e))))

# ---------------- Fig: primitives
fig, ax = plt.subplots(figsize=(6.6, 2.7))
x = np.arange(len(PRIM))
w = 0.27
for i in range(3):
    ax.bar(x + (i - 1) * w, [p[2][i] for p in PRIM], w, label=PLAT[i], color=COL[i])
ax.set_yscale("log")
ax.set_xticks(x)
ax.set_xticklabels([p[0] for p in PRIM], rotation=35, ha="right")
ax.set_ylabel("Time per operation (ms)")
ax.legend(ncol=3, loc="upper left")
fig.tight_layout()
fig.savefig(f"{OUT}/fig_prim.pdf")
plt.close(fig)

# ---------------- Fig: computation
fig, ax = plt.subplots(figsize=(6.6, 2.9))
names = [s[0] for s in summary["comp"]]
x = np.arange(len(names))
for i in range(3):
    vals = [s[1][i] for s in summary["comp"]]
    bars = ax.bar(x + (i - 1) * w, vals, w, label=PLAT[i], color=COL[i])
    for j, (_, _, lb) in enumerate(SCHEMES):
        if lb:
            bars[j].set_hatch("///")
ax.set_yscale("log")
ax.set_xticks(x)
ax.set_xticklabels(names, rotation=30, ha="right")
ax.set_ylabel("Computation (ms)")
ax.legend(ncol=3, loc="upper right")
fig.tight_layout()
fig.savefig(f"{OUT}/fig_comp.pdf")
plt.close(fig)

# ---------------- Fig: communication
ms = costs["message_sizes"]
COMP = [("SPUFChain", 2592, 6), ("TS-PAID", 2208, 4), ("Gai et al.", 1536, 2),
        ("Sun et al.", 2016, 3), ("Wang et al.", 2304, 3)]
dn, du = ms["delegation"]["total_native"], ms["delegation"]["total_uniform"]
an, au = ms["access"]["total_native"], ms["access"]["total_uniform"]
fig, axs = plt.subplots(1, 2, figsize=(6.8, 2.8), gridspec_kw={"width_ratios": [1.15, 1]})
labels = [c[0] for c in COMP] + ["LSACP\ndelegation", "LSACP\naccess"]
nat = [c[1] for c in COMP] + [dn, an]
uni = [c[1] for c in COMP] + [du, au]
x = np.arange(len(labels))
axs[0].bar(x - 0.2, nat, 0.4, label="as specified / native", color=COL[0])
axs[0].bar(x + 0.2, uni, 0.4, label="uniform 160/256-bit convention", color=COL[1])
axs[0].set_xticks(x)
axs[0].set_xticklabels(labels, rotation=35, ha="right", fontsize=7.5)
axs[0].set_ylabel("Bits per run")
axs[0].legend(loc="upper left", fontsize=6.8)
axs[0].set_title("(a) Total communication per run")
k = np.arange(1, 51)
axs[1].plot(k, (dn + (k - 1) * an) / k, color=COL[0], lw=1.8, label="LSACP (native)")
axs[1].plot(k, (du + (k - 1) * au) / k, color=COL[1], lw=1.8, label="LSACP (uniform)")
for j, (n, b, _) in enumerate(COMP):
    axs[1].axhline(b, color=COL[j + 2], ls="--", lw=1, label=n)
axs[1].set_xlabel("Sessions per delegation $k$")
axs[1].set_ylabel("Bits per session")
axs[1].set_ylim(0, 4600)
axs[1].legend(fontsize=6.0, ncol=3, loc="upper right", columnspacing=0.8, handlelength=1.6)
axs[1].set_title("(b) Amortised cost per session")
fig.tight_layout()
fig.savefig(f"{OUT}/fig_comm.pdf")
plt.close(fig)
be = {}
for n, b, _ in COMP:
    be[n] = (int(np.ceil((dn - an) / (b - an))), int(np.ceil((du - au) / (b - au))))
summary["breakeven"] = be

# ---------------- Fig: energy
fig, ax = plt.subplots(figsize=(6.6, 2.8))
x = np.arange(len(names))
for i in range(3):
    vals = [s[3][i] for s in summary["comp"]]
    bars = ax.bar(x + (i - 1) * w, vals, w, label=f"{PLAT[i]} ({POWER[i]:.0f} W)", color=COL[i])
    for j, (_, _, lb) in enumerate(SCHEMES):
        if lb:
            bars[j].set_hatch("///")
ax.set_yscale("log")
ax.set_xticks(x)
ax.set_xticklabels(names, rotation=30, ha="right")
ax.set_ylabel("Energy per run (mJ)")
ax.legend(ncol=3, loc="upper right", fontsize=7)
fig.tight_layout()
fig.savefig(f"{OUT}/fig_energy.pdf")
plt.close(fig)

# ---------------- Fig: tag hardware
th = costs["tag_hardware"]
f = np.logspace(np.log10(100), np.log10(10000), 60)  # kHz
fig, ax = plt.subplots(figsize=(5.2, 2.8))
for j, ph in enumerate(["delegation", "access", "revocation"]):
    ax.plot(f, th[ph]["compressions_nocache"] * 1128 / f, color=COL[j], lw=1.8, label=f"{ph} (no caching)")
    ax.plot(f, th[ph]["compressions_cached"] * 1128 / f, color=COL[j], lw=1.2, ls="--", label=f"{ph} (cached pads)")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Tag clock frequency (kHz)")
ax.set_ylabel("On-tag computation (ms)")
ax.legend(fontsize=6.5, ncol=2)
fig.tight_layout()
fig.savefig(f"{OUT}/fig_tag.pdf")
plt.close(fig)

# ---------------- Fig: real server
lv = srv["levels"]
C = [l["concurrency"] for l in lv]
fig, ax = plt.subplots(figsize=(5.2, 2.7))
ax.plot(C, [l["throughput_per_s"] for l in lv], "o-", color=COL[0], label="throughput")
ax.set_xscale("log")
ax.set_xlabel("Concurrent delegations (closed loop)")
ax.set_ylabel("Delegations per second", color=COL[0])
ax.set_ylim(0, 3000)
ax2 = ax.twinx()
ax2.plot(C, [l["lat_mean_ms"] for l in lv], "s--", color=COL[5], label="mean latency")
ax2.plot(C, [l["lat_p95_ms"] for l in lv], "^:", color=COL[3], label="95th percentile")
ax2.set_yscale("log")
ax2.set_ylabel("Latency (ms)", color=COL[5])
ax2.grid(False)
h1, l1 = ax.get_legend_handles_labels()
h2, l2 = ax2.get_legend_handles_labels()
ax.legend(h1 + h2, l1 + l2, loc="lower right", fontsize=7)
fig.tight_layout()
fig.savefig(f"{OUT}/fig_server.pdf")
plt.close(fig)

# ---------------- Fig: scalability latency
order = ["SPUFChain", "TS-PAID", "Gai et al.", "Sun et al.*", "Wang et al.*", "LSACP (access)", "LSACP (delegation)"]
mk = ["o", "s", "^", "v", "D", "*", "P"]
fig, axs = plt.subplots(1, 2, figsize=(6.8, 2.9), sharey=True)
for a, dep, title in ((axs[0], "CLOUD", "(a) Cloud server (one-way delay 10 ms)"),
                      (axs[1], "EDGE", "(b) Edge server (one-way delay 1 ms)")):
    for j, sch in enumerate(order):
        rows = sorted([r for r in sim["rows"] if r["deploy"] == dep and r["loss"] == 0.0 and r["scheme"] == sch],
                      key=lambda r: r["N"])
        a.plot([r["N"] for r in rows], [r["mean_ms"] for r in rows], marker=mk[j], ms=4, color=COL[j],
               lw=1.3, label=sch)
    a.set_xscale("log")
    a.set_yscale("log")
    a.set_xlabel("Number of tagged items $N$")
    a.set_title(title)
axs[0].set_ylabel("Mean latency (ms)")
axs[0].set_ylim(2, 1e6)
axs[1].legend(fontsize=6.3, loc="upper left")
fig.tight_layout()
fig.savefig(f"{OUT}/fig_scal.pdf")
plt.close(fig)

# ---------------- Fig: utilisation and throughput
fig, axs = plt.subplots(1, 2, figsize=(6.8, 2.8))
for j, sch in enumerate(order):
    rows = sorted([r for r in sim["rows"] if r["deploy"] == "CLOUD" and r["loss"] == 0.0 and r["scheme"] == sch],
                  key=lambda r: r["N"])
    if sch != "LSACP (access)":
        axs[0].plot([r["N"] for r in rows], [max(r["rho"], 1e-5) for r in rows], marker=mk[j], ms=4,
                    color=COL[j], lw=1.3, label=sch)
    axs[1].plot([r["N"] for r in rows], [r["throughput_per_s"] for r in rows], marker=mk[j], ms=4,
                color=COL[j], lw=1.3, label=sch)
axs[0].axhline(1.0, color="k", ls="--", lw=1)
axs[0].text(12, 1.3, "saturation ($\\rho=1$)", fontsize=7)
for a in axs:
    a.set_xscale("log")
    a.set_yscale("log")
    a.set_xlabel("Number of tagged items $N$")
axs[0].set_ylabel("Server utilisation $\\rho$")
axs[0].set_title("(a) Offered server load")
axs[1].set_ylabel("Completed runs per second")
axs[1].set_title("(b) Throughput")
axs[1].legend(fontsize=6, loc="upper left")
fig.tight_layout()
fig.savefig(f"{OUT}/fig_util.pdf")
plt.close(fig)

print(json.dumps(summary, indent=1))
