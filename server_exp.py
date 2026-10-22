"""
Real-server experiment: the Cloud Server runs as a separate OS process
serving the delegation phase (M1, M4->M5, M8->M9) over TCP (asyncio).
A client process drives C concurrent delegations in closed loop; each
coroutine owns its own MF/SP/ET triple.  For each concurrency level we
record throughput, latency percentiles, server CPU time per delegation,
server CPU utilisation and server memory (peak RSS).

Both processes share the single vCPU of the test VM, so throughput is a
lower bound on what a dedicated server would sustain.
"""
import asyncio
import json
import multiprocessing as mp
import os
import resource
import statistics
import struct
import time

import lsacp as L

HOST, PORT = "127.0.0.1", 47811
POL = L.pack_pol(0xFFFF, 50)
LEVELS = [1, 5, 10, 25, 50, 100, 200]
DURATION = 12.0      # seconds per level (after 2 s warm-up)
WARMUP = 2.0

SPEC = {  # message type -> ordered (field, length)
    1: ("M1", [("id_MF", 16), ("ctr", 4), ("T", 4), ("X", 36), ("a1", 16)]),
    4: ("M4", [("id_SP", 16), ("nS", 16), ("nE", 16), ("kappa", 16), ("Y", 16), ("b1", 16)]),
    8: ("M8", [("nC", 16), ("rho", 16), ("b2", 16)]),
    5: ("M5", [("nC", 16), ("ES", 36), ("tauS", 16), ("EE", 52), ("tauE", 16)]),
    9: ("M9", [("ctr", 4), ("st", 1), ("a2", 16)]),
    2: ("ACK", [("ok", 1)]),
    3: ("ERR", [("ok", 1)]),
}
TYPE_OF = {v[0]: k for k, v in SPEC.items()}


def encode(msg):
    t = TYPE_OF[msg.name]
    body = b"".join(msg[f] for f, _ in SPEC[t][1])
    return struct.pack(">BH", t, len(body)) + body


async def read_msg(reader):
    hdr = await reader.readexactly(3)
    t, n = struct.unpack(">BH", hdr)
    body = await reader.readexactly(n)
    name, fields = SPEC[t]
    m, off = L.Msg(name), 0
    for f, ln in fields:
        m[f] = body[off:off + ln]
        off += ln
    return m


def build_worlds(n):
    cs = L.CloudServer()
    worlds = []
    for _ in range(n):
        idm, km = cs.register_mf()
        ide, ke = cs.register_et(owner=idm)
        ids, ks = cs.register_sp()
        worlds.append((L.Manufacturer(idm, km), L.Supplier(ids, ks), L.ETag(ide, ke)))
    return cs, worlds


# ------------------------------------------------------------------ server
def server_main(cs, ready, cmd_q, res_q, stop_evt):
    per_req = []

    async def handle(reader, writer):
        try:
            while True:
                m = await read_msg(reader)
                t0 = time.process_time_ns()
                try:
                    if m.name == "M1":
                        cs.on_M1(m, int(time.time()))
                        resp = L.Msg("ACK", ok=b"\x01")
                    elif m.name == "M4":
                        resp = cs.on_M4(m)
                    elif m.name == "M8":
                        resp = cs.on_M8(m)
                    else:
                        resp = L.Msg("ERR", ok=b"\x00")
                except L.Reject:
                    resp = L.Msg("ERR", ok=b"\x00")
                per_req.append((m.name, time.process_time_ns() - t0))
                writer.write(encode(resp))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()

    async def main():
        srv = await asyncio.start_server(handle, HOST, PORT, backlog=1024)
        ready.set()
        loop = asyncio.get_running_loop()
        marks = []
        while not stop_evt.is_set():
            await asyncio.sleep(0.05)
            cmd = None
            try:
                cmd = cmd_q.get_nowait()
            except Exception:
                pass
            if cmd == "mark":
                per_req.clear()
                marks = [time.process_time(), time.perf_counter()]
            elif cmd == "report":
                cpu = time.process_time() - marks[0]
                wall = time.perf_counter() - marks[1]
                deleg_cpu = {}
                for name, ns in per_req:
                    deleg_cpu.setdefault(name, []).append(ns / 1e6)
                res_q.put({
                    "server_cpu_s": cpu, "wall_s": wall,
                    "cpu_util": cpu / wall if wall else 0.0,
                    "handler_ms": {k: statistics.mean(v) for k, v in deleg_cpu.items()},
                    "maxrss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    "sessions_open": len(cs.sessions),
                })
                await asyncio.sleep(0.2)
        srv.close()
    asyncio.run(main())


# ------------------------------------------------------------------ client
async def one_delegation(world, reader, writer):
    mf, sp, et = world
    m1 = mf.request_delegation(sp.id, et.id, POL, int(time.time()))
    writer.write(encode(m1)); await writer.drain()
    r = await read_msg(reader)
    if r.name != "ACK":
        raise RuntimeError("M1 rejected")
    m3 = et.on_query_cs()
    writer.write(encode(sp.start_delegation(et.id, m3))); await writer.drain()
    m5 = await read_msg(reader)
    if m5.name != "M5":
        raise RuntimeError("M4 rejected")
    m7, _ = et.on_M6(sp.on_M5(m5))
    m8, _ = sp.on_M7(m7)
    writer.write(encode(m8)); await writer.drain()
    m9 = await read_msg(reader)
    if m9.name != "M9":
        raise RuntimeError("M8 rejected")
    mf.on_M9(m9)


async def client_level(worlds, C, cmd_q, res_q):
    lat, done, errors = [], [0], [0]
    stop_at = [None]
    measuring = [False]

    async def worker(w):
        reader, writer = await asyncio.open_connection(HOST, PORT)
        while stop_at[0] is None or time.perf_counter() < stop_at[0]:
            t0 = time.perf_counter()
            try:
                await one_delegation(w, reader, writer)
                if measuring[0]:
                    lat.append((time.perf_counter() - t0) * 1e3)
                    done[0] += 1
            except RuntimeError:
                errors[0] += 1
        writer.close()

    tasks = [asyncio.create_task(worker(worlds[i])) for i in range(C)]
    await asyncio.sleep(WARMUP)
    cmd_q.put("mark")
    measuring[0] = True
    t_start = time.perf_counter()
    c0 = time.process_time()
    stop_at[0] = t_start + DURATION
    await asyncio.gather(*tasks)
    wall = time.perf_counter() - t_start
    client_cpu = time.process_time() - c0
    cmd_q.put("report")
    srv = res_q.get(timeout=10)
    lat.sort()
    q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))]
    return {"concurrency": C, "completed": done[0], "errors": errors[0],
            "throughput_per_s": done[0] / wall,
            "lat_mean_ms": statistics.mean(lat), "lat_p50_ms": q(0.50),
            "lat_p95_ms": q(0.95), "lat_p99_ms": q(0.99),
            "client_cpu_per_deleg_ms": 1e3 * client_cpu / max(1, done[0]),
            "server": srv,
            "server_cpu_per_deleg_ms": 1e3 * srv["server_cpu_s"] / max(1, done[0])}


def main():
    cs, worlds = build_worlds(max(LEVELS))
    ready, stop_evt = mp.Event(), mp.Event()
    cmd_q, res_q = mp.Queue(), mp.Queue()
    p = mp.Process(target=server_main, args=(cs, ready, cmd_q, res_q, stop_evt), daemon=True)
    p.start()
    ready.wait(10)
    results = []
    for C in LEVELS:
        r = asyncio.run(client_level(worlds, C, cmd_q, res_q))
        results.append(r)
        print(f"C={C:4d} thr={r['throughput_per_s']:8.1f}/s mean={r['lat_mean_ms']:7.2f} ms "
              f"p95={r['lat_p95_ms']:7.2f} ms srvCPU/deleg={r['server_cpu_per_deleg_ms']:.3f} ms "
              f"util={r['server']['cpu_util']:.2f} rss={r['server']['maxrss_kb']} kB err={r['errors']}")
    stop_evt.set()
    p.join(3)
    # per-session memory of CS state (tracemalloc on a fresh server)
    import tracemalloc
    cs2, w2 = build_worlds(1000)
    tracemalloc.start()
    s0 = tracemalloc.take_snapshot()
    for mf, sp, et in w2:
        m1 = mf.request_delegation(sp.id, et.id, POL, int(time.time()))
        cs2.on_M1(m1, int(time.time()))
        cs2.on_M4(sp.start_delegation(et.id, et.on_query_cs()))
    s1 = tracemalloc.take_snapshot()
    inflight = sum(st.size_diff for st in s1.compare_to(s0, "filename"))
    tracemalloc.stop()
    os.makedirs("results", exist_ok=True)
    with open("results/server.json", "w") as f:
        json.dump({"levels": results, "duration_s": DURATION,
                   "python_bytes_per_inflight_session": inflight / 1000}, f, indent=1)
    print("bytes per in-flight session (Python objects):", inflight / 1000)


if __name__ == "__main__":
    mp.set_start_method("fork")
    main()
