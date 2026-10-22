"""
Cost extraction and micro-benchmarks for the revised LSACP.

Outputs results/costs.json with:
  * per-entity HMAC/XOR counts per phase (from the instrumented implementation)
  * exact message sizes (native and uniform 160/256-bit convention)
  * storage per entity (from the state layout)
  * SHA-256 compression-function counts on the tag
  * wall-clock / CPU timings on the machine running the script
"""
import json
import os
import platform
import statistics
import time
import hmac
import hashlib

import lsacp as L

POL = L.pack_pol(0xFFFF, 50)
out = {}

# ------------------------------------------------------------ op counts
def counts(phase):
    cs, mf, et, (sp,) = L.setup_world()
    if phase in ("access", "revocation"):
        L.run_delegation(cs, mf, sp, et, POL)
    for e in (cs, mf, et, sp):
        e.cnt.reset()
    log = []
    if phase == "delegation":
        L.run_delegation(cs, mf, sp, et, POL, log=log)
    elif phase == "access":
        L.run_access(sp, et, log=log)
    else:
        L.run_revocation(cs, mf, et, log=log)
    c = {n: {"hmac": e.cnt.hmac, "xor": e.cnt.xor}
         for n, e in (("CS", cs), ("MF", mf), ("ET", et), ("SP", sp))}
    c["total"] = {"hmac": sum(v["hmac"] for v in c.values()),
                  "xor": sum(v["xor"] for v in c.values())}
    return c, log


def counts_resync():
    """Delegation when ET and SP are both one key step ahead of CS."""
    cs, mf, et, (sp,) = L.setup_world()
    m1 = mf.request_delegation(sp.id, et.id, POL, 1000); cs.on_M1(m1, 1000)
    m3 = et.on_query_cs(); m5 = cs.on_M4(sp.start_delegation(et.id, m3))
    m7, _ = et.on_M6(sp.on_M5(m5)); sp.on_M7(m7)        # M8 lost
    cs.sessions.clear()
    for e in (cs, mf, et, sp):
        e.cnt.reset()
    L.run_delegation(cs, mf, sp, et, POL)
    return {"CS": {"hmac": cs.cnt.hmac, "xor": cs.cnt.xor}}


phases = {}
logs = {}
for ph in ("delegation", "access", "revocation"):
    phases[ph], logs[ph] = counts(ph)
phases["delegation_cs_worst_resync"] = counts_resync()
out["op_counts"] = phases

# ------------------------------------------------------------ message sizes
FIELD_TYPES = {
    "id_MF": ["ID"], "id_SP": ["ID"], "ctr": ["CTR"], "T": ["TS"], "st": ["ST"],
    "nE": ["N"], "nS": ["N"], "nC": ["N"], "nC2": ["N"], "mE": ["N"], "mS": ["N"],
    "kappa": ["TAG"], "Y": ["ID"],
    "a1": ["TAG"], "a2": ["TAG"], "a3": ["TAG"], "a": ["TAG"], "b1": ["TAG"],
    "b2": ["TAG"], "tauS": ["TAG"], "tauE": ["TAG"], "sig1": ["TAG"],
    "sig2": ["TAG"], "rho": ["TAG"], "RTag": ["TAG"], "Rack": ["TAG"],
    "ES": ["KEY", "POL"], "EE": ["KEY", "ID", "POL"],
}


def x_types(msg):
    if msg.name == "M1":
        return ["ID", "ID", "POL"]
    return ["ID"]                           # R0: X masks id_ET only


def size(msg, conv):
    bits = 0
    for f in msg:
        types = x_types(msg) if f == "X" else FIELD_TYPES[f]
        bits += sum(conv[t] for t in types)
    return bits


NATIVE = {"ID": 128, "N": 128, "TAG": 128, "H": 32, "CTR": 32, "TS": 32,
          "POL": 32, "ST": 8, "KEY": 256}
UNIFORM = dict(NATIVE, ID=160, N=160, TAG=256)

relabel = {"revocation": {"M3": "R2"}}
sizes = {}
for ph, log in logs.items():
    rows = []
    for m in log:
        name = relabel.get(ph, {}).get(m.name, m.name)
        assert size(m, NATIVE) == m.size_bits(), (ph, m.name)
        rows.append({"msg": name, "fields": list(m.keys()),
                     "native": size(m, NATIVE), "uniform": size(m, UNIFORM)})
    sizes[ph] = {"messages": rows,
                 "total_native": sum(r["native"] for r in rows),
                 "total_uniform": sum(r["uniform"] for r in rows),
                 "n_messages": len(rows)}
air = {"delegation": ["M2", "M3", "M6", "M7"], "access": ["A1", "A2", "A3", "A4"],
       "revocation": ["R1", "R2", "R3", "R4"]}
for ph in sizes:
    sizes[ph]["air_native"] = sum(r["native"] for r in sizes[ph]["messages"]
                                  if r["msg"] in air[ph])
out["message_sizes"] = sizes

# ------------------------------------------------------------ storage (bits)
out["storage_bits"] = {
    "ET": {"id_ET": 128, "k_ET": 256, "s_j": 256, "id_SP": 128, "pol": 32,
           "j": 16, "pending_challenge": 128, "mode_flag": 8},
    "SP_base": {"id_SP": 128, "k_SP": 256},
    "SP_per_tag": {"id_ET": 128, "s_j": 256, "pol": 32},
    "MF": {"id_MF": 128, "k_MF": 256, "ctr": 32},
    "CS_per_MF": {"id_MF": 128, "k_MF": 256, "last_ctr": 32},
    "CS_per_SP": {"id_SP": 128, "k_SP": 256},
    "CS_per_ET": {"id_ET": 128, "k_ET": 256, "owner": 128},
    "CS_per_active_delegation": {"id_SP": 128, "id_MF": 128, "pol": 32, "status": 8},
    "CS_per_inflight_session": {"n_C": 128, "s": 256, "n_E": 128, "id_ET": 128,
                                "id_SP": 128, "ctr": 32, "pol": 32},
}
out["storage_totals"] = {k: sum(v.values()) for k, v in out["storage_bits"].items()}

# ------------------------------------------------------------ tag compressions
def compressions(msg_len, cached):
    inner = -(-(64 + msg_len + 9) // 64)
    outer = 2
    return inner + outer - (2 if cached else 0)


def tag_trace(phase):
    """Record (key_id, message length) of every HMAC the tag evaluates."""
    trace = []
    orig_F = L.F

    def F_rec(cnt, key, label, *fields):
        if cnt is et.cnt:
            trace.append((key, len(L.L[label] + b"".join(fields))))
        return orig_F(cnt, key, label, *fields)

    cs, mf, et, (sp,) = L.setup_world()
    if phase != "delegation":
        L.run_delegation(cs, mf, sp, et, POL)
    L.F = F_rec
    try:
        if phase == "delegation":
            L.run_delegation(cs, mf, sp, et, POL)
        elif phase == "access":
            L.run_access(sp, et)
        else:
            L.run_revocation(cs, mf, et)
    finally:
        L.F = orig_F
    nocache = sum(compressions(n, False) for _, n in trace)
    seen, cache = set(), 0
    for k, n in trace:
        cache += compressions(n, k in seen)
        seen.add(k)
    return {"hmac_calls": len(trace), "compressions_nocache": nocache,
            "compressions_cached": cache}


CYCLES_PER_BLOCK = 1128          # Feldhofer & Rechberger (2006), SHA-256 core
tag = {ph: tag_trace(ph) for ph in ("delegation", "access", "revocation")}
for ph, v in tag.items():
    v["latency_ms"] = {}
    for f_khz in (100, 1000, 4000, 13560):
        v["latency_ms"][str(f_khz)] = {
            "nocache": round(v["compressions_nocache"] * CYCLES_PER_BLOCK / f_khz, 2),
            "cached": round(v["compressions_cached"] * CYCLES_PER_BLOCK / f_khz, 2)}
out["tag_hardware"] = tag

# ------------------------------------------------------------ timings
def timeit(fn, reps=1000, warm=100):
    for _ in range(warm):
        fn()
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn()
        xs.append((time.perf_counter_ns() - t0) / 1e6)
    return {"mean_ms": statistics.mean(xs), "sd_ms": statistics.stdev(xs),
            "median_ms": statistics.median(xs), "reps": reps}


k32, m64 = L.rnd(32), L.rnd(64)
a32, b32 = L.rnd(32), L.rnd(32)
prim = {
    "HMAC-SHA-256 (32-B key, 64-B msg)": timeit(lambda: hmac.new(k32, m64, hashlib.sha256).digest()),
    "SHA-256 (64-B msg)": timeit(lambda: hashlib.sha256(m64).digest()),
    "XOR (32 B)": timeit(lambda: bytes(x ^ y for x, y in zip(a32, b32))),
}
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    prim["ECDH P-256 (point mult.)"] = timeit(lambda: sk.exchange(ec.ECDH(), pk), reps=500)
except Exception as exc:                       # pragma: no cover
    prim["ECDH P-256 (point mult.)"] = {"error": str(exc)}
out["vm_primitives"] = prim


def role_times(phase, reps=1000):
    """Per-role CPU time of complete protocol runs (process_time)."""
    acc = {"CS": [], "MF": [], "ET": [], "SP": [], "total": []}
    handlers = {
        "CS": ["on_M1", "on_M4", "on_M8", "on_R0", "on_R2", "on_R4"],
        "MF": ["request_delegation", "on_M9", "request_revocation", "on_R5"],
        "ET": ["on_query_cs", "on_M6", "on_query_acc", "on_A3", "on_R3"],
        "SP": ["start_delegation", "on_M5", "on_M7", "on_A2", "on_A4"],
    }
    classes = {"CS": L.CloudServer, "MF": L.Manufacturer, "ET": L.ETag, "SP": L.Supplier}
    bucket = {}
    originals = {}
    for role, cls in classes.items():
        for h in handlers[role]:
            f = getattr(cls, h)
            originals[(cls, h)] = f

            def wrap(f=f, role=role):
                def g(*a, **kw):
                    t0 = time.perf_counter_ns()
                    try:
                        return f(*a, **kw)
                    finally:
                        bucket[role] = bucket.get(role, 0) + time.perf_counter_ns() - t0
                return g
            setattr(cls, h, wrap())
    try:
        for i in range(reps + 50):
            cs, mf, et, (sp,) = L.setup_world()
            if phase != "delegation":
                L.run_delegation(cs, mf, sp, et, POL)
            bucket.clear()
            t0 = time.perf_counter_ns()
            if phase == "delegation":
                L.run_delegation(cs, mf, sp, et, POL)
            elif phase == "access":
                L.run_access(sp, et)
            else:
                L.run_revocation(cs, mf, et)
            tot = time.perf_counter_ns() - t0
            if i >= 50:
                for r in ("CS", "MF", "ET", "SP"):
                    acc[r].append(bucket.get(r, 0) / 1e6)
                acc["total"].append(tot / 1e6)
    finally:
        for (cls, h), f in originals.items():
            setattr(cls, h, f)
    return {r: {"mean_ms": statistics.mean(v), "sd_ms": statistics.stdev(v)}
            for r, v in acc.items()}


out["vm_protocol"] = {ph: role_times(ph) for ph in ("delegation", "access", "revocation")}
out["platform"] = {"python": platform.python_version(), "machine": platform.machine(),
                   "processor": "Intel Xeon (Cascade Lake) @ 2.80 GHz, 1 vCPU, KVM",
                   "openssl": __import__("ssl").OPENSSL_VERSION}

os.makedirs("results", exist_ok=True)
with open("results/costs.json", "w") as f:
    json.dump(out, f, indent=1)
print(json.dumps({k: out[k] for k in ("op_counts", "storage_totals", "tag_hardware")}, indent=1))
print(json.dumps({ph: {k: v for k, v in sizes[ph].items() if k != "messages"} for ph in sizes}, indent=1))
print(json.dumps(out["vm_primitives"], indent=1))
print(json.dumps(out["vm_protocol"], indent=1))
