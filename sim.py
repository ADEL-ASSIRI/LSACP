"""
Trace-driven discrete-event simulation of authentication latency and server
load for N = 10 ... 10,000 tagged items (Section 6.8 of the manuscript).

Model (all parameters are listed in PARAMS and in Table 13 of the paper):
  * Each node issues authentication requests as a Poisson process with rate
    LAMBDA_ACC; LSACP nodes additionally issue delegations with rate
    LAMBDA_DEL.  The superposition over N nodes is Poisson with rate
    N * lambda, which is how arrivals are generated.
  * Every message of a session traverses either the air interface
    (106 kbit/s, ISO/IEC 14443 base rate, plus a fixed per-frame overhead) or a
    WAN link (one-way delay D0 + exponential jitter).  Each transmission is
    lost independently with probability p and retransmitted after an RTO.
  * The server is a single FIFO queue (one worker).  Each session that
    involves the server occupies it for S seconds, where S is the scheme's
    complete computation cost from the cost model (Table 4 laptop timings);
    charging every operation to the server is applied uniformly to all
    schemes and is conservative for all of them.  Waiting times follow the
    exact Lindley recursion for a FIFO single-server queue.
  * Competing schemes are emulated from their published operation counts and
    message counts; they are NOT re-implemented.  LSACP's server cost is
    charged in the same way, so the comparison is like-for-like.
"""
import json
import os
import numpy as np

# Table 4 (authors' testbed), ms per operation
T_LAPTOP = {"H": 0.025, "HMAC": 0.031, "PUF": 0.220, "SED": 0.016, "CH": 0.210,
            "BP": 5.400, "SV": 0.160, "IPFS": 0.500, "XOR": 0.001}
T_GALAXY = {"HMAC": 0.047, "XOR": 0.002}

PARAMS = {
    "LAMBDA_ACC": 1 / 60.0,      # authentications per node per second
    "LAMBDA_DEL": 1 / 3600.0,    # LSACP delegations per node per second
    "AIR_RATE_BPS": 106_000,
    "AIR_FRAME_OVERHEAD_S": 0.5e-3,
    "WAN_BW_BPS": 10_000_000,
    "RTO_AIR_S": 5e-3,
    "RTO_WAN_S": 0.200,
    "CLOUD": {"D0": 10e-3, "JITTER_MEAN": 2e-3},
    "EDGE": {"D0": 1e-3, "JITTER_MEAN": 0.2e-3},
    "T_WARM_S": 30.0,
    "T_MEAS_S": 300.0,
    "REPLICATIONS": 5,
    "MIN_SAMPLES": 2000,         # horizon is extended until this many sessions
    "NODES": [10, 50, 100, 500, 1000, 5000, 10000],
    "LOSS": [0.0, 0.01, 0.05],
}

# Competing schemes: server-side cost model (ms, laptop) and message plan.
COMPETITORS = {
    "SPUFChain": {"S_ms": 20 * T_LAPTOP["H"] + 4 * T_LAPTOP["PUF"], "msgs": 6, "bits": 2592},
    "TS-PAID": {"S_ms": 16 * T_LAPTOP["H"] + 7 * T_LAPTOP["CH"] + 6 * T_LAPTOP["SED"], "msgs": 4, "bits": 2208},
    "Gai et al.": {"S_ms": 3 * T_LAPTOP["BP"] + 32 * T_LAPTOP["H"], "msgs": 2, "bits": 1536},
    "Sun et al.*": {"S_ms": 8 * T_LAPTOP["H"] + T_LAPTOP["IPFS"] + T_LAPTOP["SV"], "msgs": 3, "bits": 2016},
    "Wang et al.*": {"S_ms": 6 * T_LAPTOP["H"] + 3 * T_LAPTOP["SED"], "msgs": 3, "bits": 2304},
}
# * lower bounds: consensus (PBFT) and ZKP costs are not primitive operations
#   and are excluded, which favours these two schemes.

# LSACP from the instrumented implementation (results/costs.json)
LSACP_DEL_S_MS = 42 * T_LAPTOP["HMAC"] + 8 * T_LAPTOP["XOR"]
HM_G = T_GALAXY["HMAC"] / 1e3
LSACP_DEL_PLAN = [  # (link, bits, device compute s before sending)
    ("air", 0, 0.0),                 # M2 query
    ("air", 256, 1 * HM_G),          # M3 (tag computes hint)
    ("wan", 768, 2 * HM_G),          # M4 (SP)
    ("server", None, None),
    ("wan", 1088, 0.0),              # M5
    ("air", 928, 6 * HM_G),          # M6 (SP processes M5)
    ("air", 256, 9 * HM_G),          # M7 (tag processes M6)
    ("done", None, 2 * HM_G),        # SP verifies sigma2
]
LSACP_ACC_PLAN = [
    ("air", 0, 0.0), ("air", 256, 1 * HM_G), ("air", 256, 2 * HM_G),
    ("air", 128, 4 * HM_G), ("done", None, 3 * HM_G)]


def link_delay(rng, n, link, bits, p, dep):
    attempts = rng.geometric(1.0 - p, size=n) if p > 0 else np.ones(n)
    if link == "air":
        base = bits / PARAMS["AIR_RATE_BPS"] + PARAMS["AIR_FRAME_OVERHEAD_S"]
        return base + (attempts - 1) * PARAMS["RTO_AIR_S"]
    d = dep["D0"] + rng.exponential(dep["JITTER_MEAN"], size=n)
    return d + bits / PARAMS["WAN_BW_BPS"] + (attempts - 1) * PARAMS["RTO_WAN_S"]


def lindley(arr, S):
    order = np.argsort(arr)
    a = arr[order]
    w = np.empty_like(a)
    free = 0.0
    for i in range(len(a)):
        start = a[i] if a[i] > free else free
        w[i] = start - a[i]
        free = start + S
    out = np.empty_like(w)
    out[order] = w
    return out


def simulate_plan(rng, N, lam, plan, S_s, p, dep):
    t_meas = max(PARAMS["T_MEAS_S"], PARAMS["MIN_SAMPLES"] / (N * lam))
    horizon = PARAMS["T_WARM_S"] + t_meas
    n = rng.poisson(N * lam * horizon)
    t0 = np.sort(rng.uniform(0, horizon, size=n))
    pre = np.zeros(n)
    post = np.zeros(n)
    seen_server = False
    for link, bits, comp in plan:
        if link == "server":
            seen_server = True
            continue
        target = post if seen_server else pre
        if comp:
            target += comp
        if link in ("air", "wan"):
            target += link_delay(rng, n, link, bits, p, dep)
    if seen_server:
        w = lindley(t0 + pre, S_s)
        lat = pre + w + S_s + post
    else:
        w = np.zeros(n)
        lat = pre
    meas = t0 >= PARAMS["T_WARM_S"]
    done_in_window = (t0 + lat) <= horizon
    return lat[meas], w[meas], int(np.sum(meas & done_in_window)), t_meas


def competitor_plan(c):
    per = c["bits"] / c["msgs"]
    plan = [("wan", per, 0.0), ("server", None, None)]
    plan += [("wan", per, 0.0)] * (c["msgs"] - 1)
    plan.append(("done", None, 0.0))
    return plan


def summarise(samples):
    means = [np.mean(l) * 1e3 for l, *_ in samples]
    p95 = [np.percentile(l, 95) * 1e3 for l, *_ in samples]
    thr = [d / tm for _, _, d, tm in samples]
    R = len(samples)
    hw = 2.776 * np.std(means, ddof=1) / np.sqrt(R) if R > 1 else 0.0
    return {"mean_ms": float(np.mean(means)), "ci95_ms": float(hw),
            "p95_ms": float(np.mean(p95)), "throughput_per_s": float(np.mean(thr))}


def run():
    res = {"params": PARAMS, "S_ms": {k: v["S_ms"] for k, v in COMPETITORS.items()},
           "LSACP_DEL_S_ms": LSACP_DEL_S_MS, "rows": []}
    for dep_name in ("CLOUD", "EDGE"):
        dep = PARAMS[dep_name]
        for p in PARAMS["LOSS"]:
            for N in PARAMS["NODES"]:
                for name, c in COMPETITORS.items():
                    S = c["S_ms"] / 1e3
                    rho = N * PARAMS["LAMBDA_ACC"] * S
                    smp = [simulate_plan(np.random.default_rng(1000 * r + N), N,
                                         PARAMS["LAMBDA_ACC"], competitor_plan(c), S, p, dep)
                           for r in range(PARAMS["REPLICATIONS"])]
                    row = {"deploy": dep_name, "loss": p, "N": N, "scheme": name,
                           "rho": rho, **summarise(smp)}
                    row["saturated"] = rho >= 1.0
                    res["rows"].append(row)
                # LSACP access sessions (local, no server)
                smp = [simulate_plan(np.random.default_rng(1000 * r + N + 7), N,
                                     PARAMS["LAMBDA_ACC"], LSACP_ACC_PLAN, 0.0, p, dep)
                       for r in range(PARAMS["REPLICATIONS"])]
                res["rows"].append({"deploy": dep_name, "loss": p, "N": N,
                                    "scheme": "LSACP (access)", "rho": 0.0,
                                    "saturated": False, **summarise(smp)})
                # LSACP delegation (CS always in the cloud)
                S = LSACP_DEL_S_MS / 1e3
                smp = [simulate_plan(np.random.default_rng(1000 * r + N + 11), N,
                                     PARAMS["LAMBDA_DEL"], LSACP_DEL_PLAN, S, p, PARAMS["CLOUD"])
                       for r in range(PARAMS["REPLICATIONS"])]
                res["rows"].append({"deploy": dep_name, "loss": p, "N": N,
                                    "scheme": "LSACP (delegation)",
                                    "rho": N * PARAMS["LAMBDA_DEL"] * S,
                                    "saturated": False, **summarise(smp)})
                print(dep_name, p, N, "done", flush=True)
    os.makedirs("results", exist_ok=True)
    with open("results/sim.json", "w") as f:
        json.dump(res, f, indent=1)


if __name__ == "__main__":
    run()
