"""
Functional and adversarial validation of the revised LSACP.

Each test returns (name, expected, observed, passed).  The script writes
results/tests.json, which is the source of Table 8 in the manuscript.
"""
import copy
import json
import os
import random

import lsacp as L

POL = L.pack_pol(0xFFFF, 50)
results = []


def record(name, expected, observed):
    results.append({"test": name, "expected": expected, "observed": observed,
                    "passed": expected == observed})


def rejects(fn, *args, **kw):
    try:
        fn(*args, **kw)
        return "accepted"
    except L.Reject:
        return "rejected"


def invariant_ok(cs, et, sp):
    """Synchronisation invariant of Proposition 1."""
    K = cs.et[et.id]["k"]
    c = L.Counter()
    ok_et = et.k in (K, L.kev(c, K))
    Ks = cs.sp[sp.id]["k"]
    ok_sp = sp.k in (Ks, L.kev(c, Ks))
    ok_s = True
    if (et.deleg is not None and et.id in sp.delegs
            and et.deleg["id"] == sp.delegs[et.id]["id"]):
        s_sp = sp.delegs[et.id]["s"]
        ok_s = et.deleg["s"] in (s_sp, L.F(c, s_sp, "RAT"))
    return ok_et and ok_sp and ok_s


# ---------------------------------------------------------------- T1 honest
cs, mf, et, (sp,) = L.setup_world()
sk0 = L.run_delegation(cs, mf, sp, et, POL)
sks = [L.run_access(sp, et) for _ in range(5)]
record("T1 honest delegation + 5 access sessions agree on keys",
       "agree", "agree" if len(set(sks + [sk0])) == 6 else "mismatch")

# ---------------------------------------------------------------- T2 replays
cs, mf, et, (sp,) = L.setup_world()
m1 = mf.request_delegation(sp.id, et.id, POL, 1000)
cs.on_M1(m1, 1000)
record("T2a replay of M1 (same counter) to CS", "rejected", rejects(cs.on_M1, m1, 1001))
m1b = mf.request_delegation(sp.id, et.id, POL, 1000)
record("T2b delayed M1 outside the 30 s window", "rejected", rejects(cs.on_M1, m1b, 1100))
cs.on_M1(m1b, 1000)
m3 = et.on_query_cs()
m4 = sp.start_delegation(et.id, m3)
m5 = cs.on_M4(m4)
record("T2c replay of M4 after ticket consumption", "rejected", rejects(cs.on_M4, m4))
m6 = sp.on_M5(m5)
record("T2d replay of M5 to SP", "rejected", rejects(sp.on_M5, m5))
m7, _ = et.on_M6(m6)
record("T2e replay of M6 to ET (challenge consumed)", "rejected", rejects(et.on_M6, m6))
et.on_query_cs()   # tag issues a fresh challenge; old M6 still useless
record("T2f replay of M6 to ET after a new challenge", "rejected", rejects(et.on_M6, m6))
m8, _ = sp.on_M7(m7)
cs.on_M8(m8)
record("T2g replay of M8 to CS", "rejected", rejects(cs.on_M8, m8))
a2 = et.on_query_acc()
a3 = sp.on_A2(et.id, a2)
a4, _ = et.on_A3(a3)
sp.on_A4(a4)
et.on_query_acc()
record("T2h replay of access message A3 to ET", "rejected", rejects(et.on_A3, a3))

# ---------------------------------------------------------------- T3 revocation
cs, mf, et, (sp,) = L.setup_world()
log = []
L.run_delegation(cs, mf, sp, et, POL, log=log)
old_m6 = [m for m in log if m.name == "M6"][0]
L.run_access(sp, et)
L.run_revocation(cs, mf, et)
record("T3a access after revocation", "rejected", rejects(L.run_access, sp, et))
et.on_query_cs()
record("T3b replay of pre-revocation M6 (re-grant attempt)", "rejected", rejects(et.on_M6, old_m6))
r0 = mf.request_revocation(et.id, 1000)
cs.on_R0(r0, 1000)
r2 = et.on_query_cs()
r3 = cs.on_R2(r2)
et.on_R3(r3)
et.on_query_cs()
record("T3c replay of RTag (R3) to ET", "rejected", rejects(et.on_R3, r3))
record("T3d new delegation after revocation succeeds", "accepted",
       rejects(L.run_delegation, cs, mf, sp, et, POL))

# ---------------------------------------------------------------- T4 insiders
cs, mf, et, (sp, sp2) = L.setup_world(n_sp=2)
m1 = mf.request_delegation(sp.id, et.id, POL, 1000)
cs.on_M1(m1, 1000)
m3 = et.on_query_cs()
m4bad = sp2.start_delegation(et.id, m3)
record("T4a registered SP' requests key package without ticket", "rejected", rejects(cs.on_M4, m4bad))
m3 = et.on_query_cs()
m4 = sp.start_delegation(et.id, m3)
m5 = cs.on_M4(m4)
m6 = sp.on_M5(m5)
forged = copy.copy(m6)
forged["sig1"] = L.rnd(L.TAG_LEN)   # SP' relays E_E but cannot prove knowledge of s
record("T4b SP' forwards E_E with its own sigma1", "rejected", rejects(et.on_M6, forged))
idm2, km2 = cs.register_mf()
mf2 = L.Manufacturer(idm2, km2)
m1x = mf2.request_delegation(sp2.id, et.id, POL, 1000)
record("T4c MF' (not owner) delegates the tag", "rejected", rejects(cs.on_M1, m1x, 1000))

# ---------------------------------------------------------------- T5 budget
cs, mf, et, (sp,) = L.setup_world()
L.run_delegation(cs, mf, sp, et, L.pack_pol(0xFFFF, 3))
L.run_access(sp, et)
L.run_access(sp, et)
record("T5 access beyond budget N_max = 3", "rejected", rejects(L.run_access, sp, et))

# ---------------------------------------------------------------- T6 handover
cs, mf, et, (sp1, sp2) = L.setup_world(n_sp=2)
L.run_delegation(cs, mf, sp1, et, POL)
L.run_access(sp1, et)
L.run_delegation(cs, mf, sp2, et, POL)
record("T6a previous supplier after handover", "rejected", rejects(L.run_access, sp1, et))
record("T6b new supplier after handover", "accepted", rejects(L.run_access, sp2, et))

# ---------------------------------------------------------------- T7 FS sanity
cs, mf, et, (sp,) = L.setup_world()
log = []
L.run_delegation(cs, mf, sp, et, POL, log=log)
m3 = [m for m in log if m.name == "M3"][0]
m5 = [m for m in log if m.name == "M5"][0]
c = L.Counter()
leaked = [et.k, sp.k, cs.et[et.id]["k"], cs.sp[sp.id]["k"]]
recovered = False
for k in leaked:
    pad = L.expand(c, k, "PE", m3["nE"] + m5["nC"], len(m5["EE"]))
    tag = L.T(c, k, "TE", m3["nE"], m5["nC"], m5["EE"])
    if tag == m5["tauE"]:
        recovered = True
record("T7a post-session keys (ET, SP, CS) open the recorded key package",
       "no", "yes" if recovered else "no")
record("T7b CS retains delegation secret after M8", "no", "yes" if cs.sessions else "no")

# ---------------------------------------------------------------- T8 desync
def drop_delegation_at(k):
    """Run delegation dropping message index k (3..9), then a clean run."""
    cs, mf, et, (sp,) = L.setup_world()
    now = 1000
    try:
        m1 = mf.request_delegation(sp.id, et.id, POL, now)
        cs.on_M1(m1, now)
        m3 = et.on_query_cs()
        if k == 3:
            raise StopIteration
        m4 = sp.start_delegation(et.id, m3)
        if k == 4:
            raise StopIteration
        m5 = cs.on_M4(m4)
        if k == 5:
            raise StopIteration
        m6 = sp.on_M5(m5)
        if k == 6:
            raise StopIteration
        m7, _ = et.on_M6(m6)
        if k == 7:
            raise StopIteration
        m8, _ = sp.on_M7(m7)
        if k == 8:
            raise StopIteration
        m9 = cs.on_M8(m8)
        if k == 9:
            raise StopIteration
    except StopIteration:
        pass
    for nC in list(cs.sessions):
        cs.expire_session(nC)
    sp.op = None
    ok_inv = invariant_ok(cs, et, sp)
    try:
        if et.deleg is None or et.id not in sp.delegs:
            L.run_delegation(cs, mf, sp, et, POL, now=now)
        L.run_access(sp, et)
        L.run_revocation(cs, mf, et, now=now)
        L.run_delegation(cs, mf, sp, et, POL, now=now)
        L.run_access(sp, et)
        return ok_inv and invariant_ok(cs, et, sp)
    except L.Reject:
        return False


for k in range(3, 10):
    record(f"T8 drop M{k} during delegation, then recover", "recovered",
           "recovered" if drop_delegation_at(k) else "stuck")


def drop_access_at(k):
    cs, mf, et, (sp,) = L.setup_world()
    L.run_delegation(cs, mf, sp, et, POL)
    a2 = et.on_query_acc()
    if k > 2:
        a3 = sp.on_A2(et.id, a2)
        if k > 3:
            a4, _ = et.on_A3(a3)
    sp.acc = None
    ok_inv = invariant_ok(cs, et, sp)
    try:
        for _ in range(3):
            L.run_access(sp, et)
        return ok_inv and invariant_ok(cs, et, sp)
    except L.Reject:
        return False


# explicit regression test: M7 lost -> SP catches up through the hint alone
cs, mf, et, (sp,) = L.setup_world()
m1 = mf.request_delegation(sp.id, et.id, POL, 1000); cs.on_M1(m1, 1000)
m3 = et.on_query_cs(); m5 = cs.on_M4(sp.start_delegation(et.id, m3))
et.on_M6(sp.on_M5(m5)); sp.op = None          # M7 never reaches SP
record("T8 M7 lost: SP resumes access without re-delegation", "accepted",
       rejects(L.run_access, sp, et))

for k in (2, 3, 4):
    record(f"T8 drop A{k} during access, then recover", "recovered",
           "recovered" if drop_access_at(k) else "stuck")


def drop_revocation_at(k):
    cs, mf, et, (sp,) = L.setup_world()
    L.run_delegation(cs, mf, sp, et, POL)
    r0 = mf.request_revocation(et.id, 1000)
    cs.on_R0(r0, 1000)
    r2 = et.on_query_cs()
    if k > 2:
        r3 = cs.on_R2(r2)
        if k > 3:
            r4 = et.on_R3(r3)
            if k > 4:
                cs.on_R4(r4, r3["nC2"])
    cs.revsess.clear()
    try:
        if et.id not in cs.revjobs:
            r0 = mf.request_revocation(et.id, 1000)
            cs.on_R0(r0, 1000)
        r2 = et.on_query_cs()
        r3 = cs.on_R2(r2)
        r4 = et.on_R3(r3)
        cs.on_R4(r4, r3["nC2"])
        L.run_delegation(cs, mf, sp, et, POL)
        L.run_access(sp, et)
        return invariant_ok(cs, et, sp)
    except L.Reject:
        return False


for k in (2, 3, 4):
    record(f"T8 drop R{k} during revocation, then recover", "recovered",
           "recovered" if drop_revocation_at(k) else "stuck")

# ---------------------------------------------------------------- T9 fuzz
def fuzz(trials, seed):
    """Random schedules with drops and replays of recorded messages."""
    rng = random.Random(seed)
    viol_inv = viol_auth = stuck = 0
    for _ in range(trials):
        cs, mf, et, (sp,) = L.setup_world()
        recorded = {"M5": [], "M6": [], "A3": [], "A4": [], "R3": []}
        for _step in range(rng.randint(3, 12)):
            op = rng.random()
            p_drop = 0.3
            try:
                if op < 0.30:                    # delegation attempt
                    m1 = mf.request_delegation(sp.id, et.id, POL, 1000)
                    cs.on_M1(m1, 1000)
                    m3 = et.on_query_cs()
                    if rng.random() < p_drop: continue
                    m4 = sp.start_delegation(et.id, m3)
                    if rng.random() < p_drop: continue
                    m5 = cs.on_M4(m4); recorded["M5"].append(m5)
                    if rng.random() < p_drop: continue
                    m6 = sp.on_M5(m5); recorded["M6"].append(m6)
                    if rng.random() < p_drop: continue
                    m7, _ = et.on_M6(m6)
                    if rng.random() < p_drop: continue
                    m8, _ = sp.on_M7(m7)
                    if rng.random() < p_drop: continue
                    mf.on_M9(cs.on_M8(m8))
                elif op < 0.65:                  # access attempt
                    a2 = et.on_query_acc()
                    if rng.random() < p_drop: continue
                    a3 = sp.on_A2(et.id, a2); recorded["A3"].append(a3)
                    if rng.random() < p_drop: continue
                    a4, _ = et.on_A3(a3); recorded["A4"].append(a4)
                    if rng.random() < p_drop: continue
                    sp.on_A4(a4)
                elif op < 0.80:                  # revocation attempt
                    if et.id not in cs.revjobs:
                        cs.on_R0(mf.request_revocation(et.id, 1000), 1000)
                    r2 = et.on_query_cs()
                    if rng.random() < p_drop: continue
                    r3 = cs.on_R2(r2); recorded["R3"].append(r3)
                    if rng.random() < p_drop: continue
                    r4 = et.on_R3(r3)
                    if rng.random() < p_drop: continue
                    cs.on_R4(r4, r3["nC2"])
                else:                            # adversarial replay
                    kind = rng.choice(list(recorded))
                    if recorded[kind]:
                        old = rng.choice(recorded[kind])
                        if kind == "M6":
                            et.on_query_cs()
                            et.on_M6(old)
                            viol_auth += 1
                        elif kind == "A3":
                            et.on_query_acc()
                            et.on_A3(old)
                            viol_auth += 1
                        elif kind == "R3":
                            et.on_query_cs()
                            et.on_R3(old)
                            viol_auth += 1
                        elif kind == "M5":
                            sp.on_M5(old)
                            viol_auth += 1
            except L.Reject:
                pass
            finally:
                sp.op = None
                sp.acc = None
                for nC in list(cs.sessions):
                    cs.expire_session(nC)
                cs.revsess.clear()
            if not invariant_ok(cs, et, sp):
                viol_inv += 1
        # recovery check: one clean revocation + delegation + access
        try:
            cs.tickets.clear()
            if et.id not in cs.revjobs:
                cs.on_R0(mf.request_revocation(et.id, 1000), 1000)
            r2 = et.on_query_cs(); r3 = cs.on_R2(r2); r4 = et.on_R3(r3)
            cs.on_R4(r4, r3["nC2"])
            L.run_delegation(cs, mf, sp, et, POL)
            L.run_access(sp, et)
        except L.Reject:
            stuck += 1
    return viol_inv, viol_auth, stuck


TRIALS = 10000
vi, va, st = fuzz(TRIALS, seed=20261019)
record(f"T9a randomised schedules ({TRIALS}): invariant violations", "0", str(vi))
record(f"T9b randomised schedules ({TRIALS}): replayed message accepted", "0", str(va))
record(f"T9c randomised schedules ({TRIALS}): parties unable to recover", "0", str(st))

os.makedirs("results", exist_ok=True)
with open("results/tests.json", "w") as f:
    json.dump(results, f, indent=1)
npass = sum(r["passed"] for r in results)
for r in results:
    print(("PASS " if r["passed"] else "FAIL ") + r["test"] + " -> " + r["observed"])
print(f"{npass}/{len(results)} passed")
