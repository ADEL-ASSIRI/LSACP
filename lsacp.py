"""
LSACP (revised) -- reference implementation.

This module implements the four roles of the revised Lightweight and Secure
Access Control Protocol (Cloud Server CS, Manufacturer MF, E-tag ET,
Supplier SP) exactly as specified in Section 4 of the manuscript.  It is
instrumented so that every HMAC evaluation and every XOR masking operation is
counted per entity, and every protocol message records the exact size of its
cryptographic payload.  The cost tables in the paper are produced from these
counters (see bench.py), not computed by hand.

Only the Python standard library is used (hmac, hashlib, secrets).
"""
import hmac
import hashlib
import secrets
import struct

# ---------------------------------------------------------------------------
# Parameters (native parameterisation, Section 4.2)
# ---------------------------------------------------------------------------
ID_LEN = 16      # identifiers, 128 bit
NONCE_LEN = 16   # nonces, 128 bit
TAG_LEN = 16     # truncated HMAC tag, t = 128 bit
HINT_LEN = 16     # key hint kappa: a full t-bit MAC, so key promotion needs unforgeable evidence
CTR_LEN = 4      # manufacturer counter, 32 bit
TS_LEN = 4       # timestamp, 32 bit (seconds)
POL_LEN = 4      # policy: 16-bit rights mask || 16-bit access budget N_max
ST_LEN = 1       # status byte
KEY_LEN = 32     # long-term keys and delegation secrets, 256 bit
DELTA_T = 30     # acceptance window for MF timestamps (seconds)

# One-byte domain-separation labels.  Each label has a fixed field layout,
# so label || fields is an injective encoding.
L = {name: bytes([i + 1]) for i, name in enumerate([
    "X1", "D1", "D9", "KH", "Y4", "D4", "PE", "TE", "PS", "TS", "A1", "A2",
    "SK", "RAT", "KEV", "RE", "D8", "AA1", "AA2", "ASK", "XR", "R0", "REV",
    "RACK", "R5"])}

ST_OK = b"\x01"
ST_REVOKED = b"\x02"


class Counter:
    """Per-entity operation counter."""

    def __init__(self):
        self.hmac = 0
        self.xor = 0

    def reset(self):
        self.hmac = 0
        self.xor = 0


def F(cnt, key, label, *fields):
    """HMAC-SHA-256(key, label || fields); counted as one HMAC evaluation."""
    cnt.hmac += 1
    return hmac.new(key, L[label] + b"".join(fields), hashlib.sha256).digest()


def T(cnt, key, label, *fields):
    """Truncated MAC tag (t = 128 bit)."""
    return F(cnt, key, label, *fields)[:TAG_LEN]


def expand(cnt, key, label, ctx, nbytes):
    """Counter-mode HMAC expansion (HKDF-Expand style) producing nbytes."""
    out = b""
    i = 1
    while len(out) < nbytes:
        out += F(cnt, key, label, ctx, bytes([i]))
        i += 1
    return out[:nbytes]


def xor(cnt, a, b):
    cnt.xor += 1
    return bytes(x ^ y for x, y in zip(a, b))


def kev(cnt, key):
    """One-way key evolution k' = HMAC(k, KEV)."""
    return F(cnt, key, "KEV")


def ct_eq(a, b):
    return hmac.compare_digest(a, b)


def rnd(n):
    return secrets.token_bytes(n)


class Msg(dict):
    """A protocol message: ordered fields; size() = payload bits."""

    def __init__(self, name, **fields):
        super().__init__(**fields)
        self.name = name

    def size_bits(self):
        return 8 * sum(len(v) for v in self.values())


def pack_pol(rights, nmax):
    return struct.pack(">HH", rights, nmax)


def unpack_pol(pol):
    return struct.unpack(">HH", pol)


class Reject(Exception):
    pass


# ---------------------------------------------------------------------------
# Cloud Server
# ---------------------------------------------------------------------------
class CloudServer:
    def __init__(self):
        self.cnt = Counter()
        self.id = rnd(ID_LEN)
        self.mf = {}        # id_MF -> {"k", "last_ctr"}
        self.sp = {}        # id_SP -> {"k"}           (current key only)
        self.et = {}        # id_ET -> {"k", "owner"}  (current key only)
        self.tickets = {}   # (id_SP, id_ET) -> {"mf", "ctr", "pol"}
        self.sessions = {}  # n_C -> transient delegation session
        self.revjobs = {}   # id_ET -> {"mf", "ctr"}
        self.revsess = {}   # n_C2 -> transient revocation session
        self.active = {}    # id_ET -> {"sp", "mf", "pol", "status"}

    # -- registration (secure channel, Section 4.3) --
    def register_mf(self):
        idm, k = rnd(ID_LEN), rnd(KEY_LEN)
        self.mf[idm] = {"k": k, "last_ctr": 0}
        return idm, k

    def register_sp(self):
        ids, k = rnd(ID_LEN), rnd(KEY_LEN)
        self.sp[ids] = {"k": k}
        return ids, k

    def register_et(self, owner):
        ide, k = rnd(ID_LEN), rnd(KEY_LEN)
        self.et[ide] = {"k": k, "owner": owner}
        return ide, k

    # -- helpers --
    def _select_et_key(self, ide, nE, kappa):
        """Choose ET's current key among {K, kev(K)} using the hint."""
        rec = self.et[ide]
        K = rec["k"]
        if ct_eq(F(self.cnt, K, "KH", nE)[:HINT_LEN], kappa):
            return K
        Kn = kev(self.cnt, K)
        if ct_eq(F(self.cnt, Kn, "KH", nE)[:HINT_LEN], kappa):
            rec["k"] = Kn          # ET is one step ahead: promote, erase K
            return Kn
        raise Reject("ET key hint does not match")

    def _select_sp_key(self, ids, verify):
        rec = self.sp[ids]
        K = rec["k"]
        if verify(K):
            return K
        Kn = kev(self.cnt, K)
        if verify(Kn):
            rec["k"] = Kn
            return Kn
        raise Reject("SP MAC invalid under both candidate keys")

    # -- Delegation --
    def on_M1(self, m, now):
        idm = m["id_MF"]
        if idm not in self.mf:
            raise Reject("unknown MF")
        rec = self.mf[idm]
        ctr = struct.unpack(">I", m["ctr"])[0]
        ts = struct.unpack(">I", m["T"])[0]
        if ctr <= rec["last_ctr"]:
            raise Reject("replayed or stale counter")
        if abs(now - ts) > DELTA_T:
            raise Reject("timestamp outside window")
        if not ct_eq(m["a1"], T(self.cnt, rec["k"], "D1", idm, m["ctr"],
                                m["T"], m["X"])):
            raise Reject("bad a1")
        pad = expand(self.cnt, rec["k"], "X1", idm + m["ctr"], len(m["X"]))
        plain = xor(self.cnt, m["X"], pad)
        ids, ide, pol = plain[:ID_LEN], plain[ID_LEN:2 * ID_LEN], plain[2 * ID_LEN:]
        if ids not in self.sp or ide not in self.et:
            raise Reject("unknown SP/ET")
        if self.et[ide]["owner"] != idm:
            raise Reject("MF does not own ET")
        rec["last_ctr"] = ctr
        self.tickets[(ids, ide)] = {"mf": idm, "ctr": m["ctr"], "pol": pol}
        return True

    def on_M4(self, m):
        ids = m["id_SP"]
        if ids not in self.sp:
            raise Reject("unknown SP")
        body = (ids, m["nS"], m["nE"], m["kappa"], m["Y"])
        kS = self._select_sp_key(
            ids, lambda K: ct_eq(m["b1"], T(self.cnt, K, "D4", *body)))
        ide = xor(self.cnt, m["Y"], F(self.cnt, kS, "Y4", m["nS"])[:ID_LEN])
        tk = self.tickets.pop((ids, ide), None)       # one-time ticket
        if tk is None:
            raise Reject("no outstanding delegation ticket")
        kE = self._select_et_key(ide, m["nE"], m["kappa"])
        nC, s = rnd(NONCE_LEN), rnd(KEY_LEN)
        ptE = s + ids + tk["pol"]
        EE = xor(self.cnt, ptE, expand(self.cnt, kE, "PE", m["nE"] + nC, len(ptE)))
        tauE = T(self.cnt, kE, "TE", m["nE"], nC, EE)
        ptS = s + tk["pol"]
        ES = xor(self.cnt, ptS, expand(self.cnt, kS, "PS", m["nS"] + nC, len(ptS)))
        tauS = T(self.cnt, kS, "TS", ide, m["nS"], nC, ES)
        self.sessions[nC] = {"s": s, "ide": ide, "ids": ids, "kE": kE,
                             "kS": kS, "nE": m["nE"], "tk": tk}
        return Msg("M5", nC=nC, ES=ES, tauS=tauS, EE=EE, tauE=tauE)

    def on_M8(self, m):
        sess = self.sessions.get(m["nC"])
        if sess is None:
            raise Reject("unknown session")
        kE1 = kev(self.cnt, sess["kE"])
        if not ct_eq(m["rho"], T(self.cnt, kE1, "RE", sess["nE"], m["nC"])):
            raise Reject("bad rho")
        kS1 = kev(self.cnt, sess["kS"])
        if not ct_eq(m["b2"], T(self.cnt, kS1, "D8", m["nC"], m["rho"])):
            raise Reject("bad b2")
        if self.et[sess["ide"]]["k"] == sess["kE"]:
            self.et[sess["ide"]]["k"] = kE1
        if self.sp[sess["ids"]]["k"] == sess["kS"]:
            self.sp[sess["ids"]]["k"] = kS1
        del self.sessions[m["nC"]]                 # erase s
        tk = sess["tk"]
        self.active[sess["ide"]] = {"sp": sess["ids"], "mf": tk["mf"],
                                    "pol": tk["pol"], "status": "active"}
        a2 = T(self.cnt, self.mf[tk["mf"]]["k"], "D9", tk["mf"], tk["ctr"], ST_OK)
        return Msg("M9", ctr=tk["ctr"], st=ST_OK, a2=a2)

    def expire_session(self, nC):
        """Timeout handling: erase s of an unconfirmed session."""
        self.sessions.pop(nC, None)

    # -- Revocation --
    def on_R0(self, m, now):
        idm = m["id_MF"]
        rec = self.mf.get(idm)
        if rec is None:
            raise Reject("unknown MF")
        ctr = struct.unpack(">I", m["ctr"])[0]
        ts = struct.unpack(">I", m["T"])[0]
        if ctr <= rec["last_ctr"] or abs(now - ts) > DELTA_T:
            raise Reject("stale revocation request")
        if not ct_eq(m["a"], T(self.cnt, rec["k"], "R0", idm, m["ctr"], m["T"], m["X"])):
            raise Reject("bad R0 tag")
        ide = xor(self.cnt, m["X"], F(self.cnt, rec["k"], "XR", idm, m["ctr"])[:ID_LEN])
        if ide not in self.et or self.et[ide]["owner"] != idm:
            raise Reject("MF does not own ET")
        rec["last_ctr"] = ctr
        self.revjobs[ide] = {"mf": idm, "ctr": m["ctr"]}
        return True

    def on_R2(self, m):
        """Reader relays (nE, kappa); CS matches against outstanding jobs."""
        for ide in list(self.revjobs):
            try:
                kE = self._select_et_key(ide, m["nE"], m["kappa"])
            except Reject:
                continue
            nC2 = rnd(NONCE_LEN)
            rtag = T(self.cnt, kE, "REV", m["nE"], nC2)
            self.revsess[nC2] = {"ide": ide, "kE": kE, "nE": m["nE"]}
            return Msg("R3", nC2=nC2, RTag=rtag)
        raise Reject("no matching revocation job")

    def on_R4(self, m, nC2):
        sess = self.revsess.get(nC2)
        if sess is None:
            raise Reject("unknown revocation session")
        kE1 = kev(self.cnt, sess["kE"])
        if not ct_eq(m["Rack"], T(self.cnt, kE1, "RACK", sess["nE"], nC2)):
            raise Reject("bad Rack")
        ide = sess["ide"]
        if self.et[ide]["k"] == sess["kE"]:
            self.et[ide]["k"] = kE1
        del self.revsess[nC2]
        job = self.revjobs.pop(ide)
        if ide in self.active:
            self.active[ide]["status"] = "revoked"
        a3 = T(self.cnt, self.mf[job["mf"]]["k"], "R5", job["mf"], job["ctr"], ST_REVOKED)
        return Msg("R5", ctr=job["ctr"], st=ST_REVOKED, a3=a3)


# ---------------------------------------------------------------------------
# Manufacturer
# ---------------------------------------------------------------------------
class Manufacturer:
    def __init__(self, idm, k):
        self.cnt = Counter()
        self.id, self.k, self.ctr = idm, k, 0
        self.pending = {}

    def request_delegation(self, ids, ide, pol, now):
        self.ctr += 1
        c = struct.pack(">I", self.ctr)
        ts = struct.pack(">I", now)
        pt = ids + ide + pol
        X = xor(self.cnt, pt, expand(self.cnt, self.k, "X1", self.id + c, len(pt)))
        a1 = T(self.cnt, self.k, "D1", self.id, c, ts, X)
        self.pending[c] = ("deleg", ids, ide)
        return Msg("M1", id_MF=self.id, ctr=c, T=ts, X=X, a1=a1)

    def on_M9(self, m):
        if m["ctr"] not in self.pending:
            raise Reject("unsolicited confirmation")
        if not ct_eq(m["a2"], T(self.cnt, self.k, "D9", self.id, m["ctr"], m["st"])):
            raise Reject("bad a2")
        return self.pending.pop(m["ctr"])

    def request_revocation(self, ide, now):
        self.ctr += 1
        c = struct.pack(">I", self.ctr)
        ts = struct.pack(">I", now)
        X = xor(self.cnt, ide, F(self.cnt, self.k, "XR", self.id, c)[:ID_LEN])
        a = T(self.cnt, self.k, "R0", self.id, c, ts, X)
        self.pending[c] = ("revoke", ide)
        return Msg("R0", id_MF=self.id, ctr=c, T=ts, X=X, a=a)

    def on_R5(self, m):
        if m["ctr"] not in self.pending:
            raise Reject("unsolicited")
        if not ct_eq(m["a3"], T(self.cnt, self.k, "R5", self.id, m["ctr"], m["st"])):
            raise Reject("bad a3")
        return self.pending.pop(m["ctr"])


# ---------------------------------------------------------------------------
# E-tag
# ---------------------------------------------------------------------------
class ETag:
    def __init__(self, ide, k):
        self.cnt = Counter()
        self.id, self.k = ide, k
        self.deleg = None       # {"s", "sp", "pol", "j"}
        self.pend = None        # ("cs", nE) or ("acc", mE)

    def on_query_cs(self):
        nE = rnd(NONCE_LEN)
        self.pend = ("cs", nE)
        return Msg("M3", nE=nE, kappa=F(self.cnt, self.k, "KH", nE)[:HINT_LEN])

    def on_M6(self, m):
        if self.pend is None or self.pend[0] != "cs":
            raise Reject("no outstanding challenge")
        nE = self.pend[1]
        if not ct_eq(m["tauE"], T(self.cnt, self.k, "TE", nE, m["nC"], m["EE"])):
            raise Reject("bad tauE")
        pt = xor(self.cnt, m["EE"], expand(self.cnt, self.k, "PE", nE + m["nC"], len(m["EE"])))
        s, ids, pol = pt[:KEY_LEN], pt[KEY_LEN:KEY_LEN + ID_LEN], pt[KEY_LEN + ID_LEN:]
        if not ct_eq(m["sig1"], T(self.cnt, s, "A1", nE, m["nC"], m["nS"])):
            raise Reject("bad sigma1")
        SK = F(self.cnt, s, "SK", m["nS"], nE, m["nC"])
        s1 = F(self.cnt, s, "RAT")
        sig2 = T(self.cnt, s, "A2", m["nS"], nE, m["nC"])
        k1 = kev(self.cnt, self.k)
        rho = T(self.cnt, k1, "RE", nE, m["nC"])
        self.k = k1                                  # erase old key
        _, nmax = unpack_pol(pol)
        self.deleg = {"s": s1, "sp": ids, "pol": pol, "j": 1, "id": m["nC"]}
        if self.deleg["j"] >= nmax:
            self.deleg = None
        self.pend = None
        return Msg("M7", sig2=sig2, rho=rho), SK

    def on_query_acc(self):
        mE = rnd(NONCE_LEN)
        self.pend = ("acc", mE)
        if self.deleg is None:
            kappa = rnd(HINT_LEN)   # indistinguishable response, no state leak
        else:
            kappa = F(self.cnt, self.deleg["s"], "KH", mE)[:HINT_LEN]
        return Msg("A2", mE=mE, kappa=kappa)

    def on_A3(self, m):
        if self.pend is None or self.pend[0] != "acc" or self.deleg is None:
            raise Reject("no outstanding access challenge")
        mE, s = self.pend[1], self.deleg["s"]
        if not ct_eq(m["sig1"], T(self.cnt, s, "AA1", mE, m["mS"])):
            raise Reject("bad access sigma1")
        SK = F(self.cnt, s, "ASK", m["mS"], mE)
        sig2 = T(self.cnt, s, "AA2", m["mS"], mE)
        self.deleg["s"] = F(self.cnt, s, "RAT")     # erase s_j
        self.deleg["j"] += 1
        _, nmax = unpack_pol(self.deleg["pol"])
        if self.deleg["j"] >= nmax:
            self.deleg = None                       # access budget exhausted
        self.pend = None
        return Msg("A4", sig2=sig2), SK

    def on_R3(self, m):
        if self.pend is None or self.pend[0] != "cs":
            raise Reject("no outstanding challenge")
        nE = self.pend[1]
        if not ct_eq(m["RTag"], T(self.cnt, self.k, "REV", nE, m["nC2"])):
            raise Reject("bad RTag")
        self.deleg = None
        k1 = kev(self.cnt, self.k)
        rack = T(self.cnt, k1, "RACK", nE, m["nC2"])
        self.k = k1
        self.pend = None
        return Msg("R4", Rack=rack)


# ---------------------------------------------------------------------------
# Supplier
# ---------------------------------------------------------------------------
class Supplier:
    def __init__(self, ids, k):
        self.cnt = Counter()
        self.id, self.k = ids, k
        self.delegs = {}    # id_ET -> {"s", "pol"}
        self.op = None      # single outstanding CS-mediated operation
        self.acc = None     # outstanding access session

    def start_delegation(self, ide, m3):
        nS = rnd(NONCE_LEN)
        Y = xor(self.cnt, ide, F(self.cnt, self.k, "Y4", nS)[:ID_LEN])
        b1 = T(self.cnt, self.k, "D4", self.id, nS, m3["nE"], m3["kappa"], Y)
        self.op = {"ide": ide, "nS": nS, "nE": m3["nE"]}
        return Msg("M4", id_SP=self.id, nS=nS, nE=m3["nE"], kappa=m3["kappa"], Y=Y, b1=b1)

    def on_M5(self, m):
        op = self.op
        if op is None:
            raise Reject("no outstanding operation")
        if not ct_eq(m["tauS"], T(self.cnt, self.k, "TS", op["ide"], op["nS"], m["nC"], m["ES"])):
            raise Reject("bad tauS")
        pt = xor(self.cnt, m["ES"], expand(self.cnt, self.k, "PS", op["nS"] + m["nC"], len(m["ES"])))
        s, pol = pt[:KEY_LEN], pt[KEY_LEN:]
        self.k = kev(self.cnt, self.k)               # evolve, erase old key
        sig1 = T(self.cnt, s, "A1", op["nE"], m["nC"], op["nS"])
        op.update({"s": s, "pol": pol, "nC": m["nC"],
                   "SK": F(self.cnt, s, "SK", op["nS"], op["nE"], m["nC"])})
        # tentative state: if M7 is lost, the hint lets SP catch up to s_1
        self.delegs[op["ide"]] = {"s": s, "pol": pol, "id": m["nC"]}
        return Msg("M6", nC=m["nC"], EE=m["EE"], tauE=m["tauE"], nS=op["nS"], sig1=sig1)

    def on_M7(self, m):
        op = self.op
        if not ct_eq(m["sig2"], T(self.cnt, op["s"], "A2", op["nS"], op["nE"], op["nC"])):
            raise Reject("bad sigma2")
        self.delegs[op["ide"]]["s"] = F(self.cnt, op["s"], "RAT")   # erase s_0
        b2 = T(self.cnt, self.k, "D8", op["nC"], m["rho"])
        SK, nC = op["SK"], op["nC"]
        self.op = None                               # erase s, nonces
        return Msg("M8", nC=nC, rho=m["rho"], b2=b2), SK

    def on_A2(self, ide, m):
        d = self.delegs.get(ide)
        if d is None:
            raise Reject("no delegation for this tag")
        s = d["s"]
        if not ct_eq(F(self.cnt, s, "KH", m["mE"])[:HINT_LEN], m["kappa"]):
            sn = F(self.cnt, s, "RAT")
            if not ct_eq(F(self.cnt, sn, "KH", m["mE"])[:HINT_LEN], m["kappa"]):
                raise Reject("tag hint matches neither candidate")
            d["s"] = sn          # tag committed last session: catch up
            s = sn
        mS = rnd(NONCE_LEN)
        self.acc = {"ide": ide, "mE": m["mE"], "mS": mS, "s": s}
        return Msg("A3", mS=mS, sig1=T(self.cnt, s, "AA1", m["mE"], mS))

    def on_A4(self, m):
        a = self.acc
        if a is None:
            raise Reject("no access session")
        if not ct_eq(m["sig2"], T(self.cnt, a["s"], "AA2", a["mS"], a["mE"])):
            raise Reject("bad access sigma2")
        SK = F(self.cnt, a["s"], "ASK", a["mS"], a["mE"])
        self.delegs[a["ide"]]["s"] = F(self.cnt, a["s"], "RAT")
        self.acc = None
        return SK


# ---------------------------------------------------------------------------
# Convenience drivers
# ---------------------------------------------------------------------------
def run_delegation(cs, mf, sp, et, pol, now=1000, log=None):
    m1 = mf.request_delegation(sp.id, et.id, pol, now)
    cs.on_M1(m1, now)
    m2 = Msg("M2")                      # payload-free reader query
    m3 = et.on_query_cs()
    m4 = sp.start_delegation(et.id, m3)
    m5 = cs.on_M4(m4)
    m6 = sp.on_M5(m5)
    m7, sk_et = et.on_M6(m6)
    m8, sk_sp = sp.on_M7(m7)
    m9 = cs.on_M8(m8)
    mf.on_M9(m9)
    assert sk_et == sk_sp
    if log is not None:
        log.extend([m1, m2, m3, m4, m5, m6, m7, m8, m9])
    return sk_et


def run_access(sp, et, log=None):
    a1 = Msg("A1")
    a2 = et.on_query_acc()
    a3 = sp.on_A2(et.id, a2)
    a4, sk_et = et.on_A3(a3)
    sk_sp = sp.on_A4(a4)
    assert sk_et == sk_sp
    if log is not None:
        log.extend([a1, a2, a3, a4])
    return sk_et


def run_revocation(cs, mf, et, now=1000, log=None):
    r0 = mf.request_revocation(et.id, now)
    cs.on_R0(r0, now)
    r1 = Msg("R1")
    r2 = et.on_query_cs()
    r3 = cs.on_R2(r2)
    r4 = et.on_R3(r3)
    r5 = cs.on_R4(r4, r3["nC2"])
    mf.on_R5(r5)
    if log is not None:
        log.extend([r0, r1, r2, r3, r4, r5])
    return True


def setup_world(n_sp=1):
    cs = CloudServer()
    idm, km = cs.register_mf()
    mf = Manufacturer(idm, km)
    ide, ke = cs.register_et(owner=idm)
    et = ETag(ide, ke)
    sps = []
    for _ in range(n_sp):
        ids, ks = cs.register_sp()
        sps.append(Supplier(ids, ks))
    return cs, mf, et, sps
