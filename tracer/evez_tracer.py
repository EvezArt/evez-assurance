#!/usr/bin/env python3
"""EVEZ-TRACER — network audit, tracing, tag machine. Stdlib only.

Scope law: nothing is probed outside a declared CIDR. Passive observation of the
local host always works; raw-socket capture requires CAP_NET_RAW and degrades
to /proc inspection when absent.
"""
import argparse, json, os, socket, sqlite3, struct, sys, threading, time
from datetime import datetime, timezone

DB = os.environ.get("TRACER_DB", "eigengraph.db")
KEY = os.environ.get("TRACER_KEY", "evez-local")
STATE = {"scope": [], "sniffing": False, "cycles": 0, "last": None, "alerts": []}

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def db():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS nodes(ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
      tags TEXT, risk REAL, eig REAL);
    CREATE TABLE IF NOT EXISTS edges(a TEXT, b TEXT, kind TEXT, seen TEXT,
      PRIMARY KEY(a,b,kind));
    CREATE TABLE IF NOT EXISTS history(ip TEXT, ts TEXT, event TEXT);
    CREATE TABLE IF NOT EXISTS samples(ts TEXT, nodes INTEGER, edges INTEGER, dominant REAL);
    """)
    return c

PORTS = {22:"ssh",80:"http",443:"https",21:"ftp",25:"smtp",53:"dns",3306:"mysql",
         5432:"postgres",6379:"redis",27017:"mongo",8080:"http-alt",18789:"openclaw-gw",
         9999:"tracer",11434:"ollama",5000:"flask",8000:"http-alt2",4444:"shell?"}
RISK = {"ssh":8,"telnet":30,"ftp":22,"redis":25,"mongo":25,"mysql":20,"shell?":40,
        "openclaw-gw":15,"http":10,"https":0,"tracer":5}

def in_scope(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return any(a in ipaddress.ip_network(s, strict=False) for s in STATE["scope"])
    except Exception:
        return False

def sniffer_proc():
    """Passive observation of this host's own socket table. No packets sent."""
    obs = {}
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = open(fn).read().splitlines()[1:]
        except Exception:
            continue
        for r in rows:
            f = r.split()
            if len(f) < 4:
                continue
            def dec(h):
                ip, port = h.split(":")
                port = int(port, 16)
                if len(ip) == 8:
                    ip = ".".join(str(int(ip[i:i+2], 16)) for i in (6, 4, 2, 0))
                else:
                    ip = "::1" if ip.strip("0") in ("", "1") else "v6"
                if ip == "0.0.0.0":
                    ip = "127.0.0.1"
                return ip, port
            lip, lp = dec(f[1]); rip, rp = dec(f[2])
            for ip, port, kind in ((rip, rp, "remote"), (lip, lp, "local")):
                if port and port != 0:
                    obs.setdefault(ip, set()).add(port)
    return obs

def upsert(c, ip, ports, peer=None):
    ts = now()
    row = c.execute("SELECT tags,first_seen FROM nodes WHERE ip=?", (ip,)).fetchone()
    tags = set(json.loads(row[0])) if row else set()
    for p in ports:
        svc = PORTS.get(p, "port%d" % p)
        tags.add("%s:%d" % (svc, p))
    if row:
        c.execute("UPDATE nodes SET last_seen=?, tags=? WHERE ip=?", (ts, json.dumps(sorted(tags)), ip))
    else:
        c.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?)", (ip, ts, ts, json.dumps(sorted(tags)), 0, 0))
    if peer and peer != ip:
        if not c.execute("SELECT 1 FROM nodes WHERE ip=?", (peer,)).fetchone():
            c.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?)", (peer, ts, ts, "[]", 0, 0))
        c.execute("INSERT OR REPLACE INTO edges VALUES(?,?,?,?)", (ip, peer, "communicates-with", ts))
    c.execute("INSERT INTO history VALUES(?,?,?)", (ip, ts, "observed:%s" % ",".join(map(str, sorted(ports)))))

def risk_of(tags):
    r = 0
    for t in tags:
        name = t.split(":")[0]
        r += RISK.get(name, 2)
    return min(100, r)

def eigen(c):
    """Dominant eigenvalue + per-node centrality via power iteration. Pure stdlib."""
    rows = c.execute("SELECT ip FROM nodes").fetchall()
    idx = {r[0]: i for i, r in enumerate(rows)}
    n = len(idx)
    if n == 0:
        return 0.0, {}
    A = [[0.0] * n for _ in range(n)]
    for a, b, _ in c.execute("SELECT a,b,kind FROM edges").fetchall():
        if a in idx and b in idx:
            A[idx[a]][idx[b]] = 1.0
            A[idx[b]][idx[a]] = 1.0
    v = [1.0 / n] * n
    lam = 0.0
    for _ in range(200):
        w = [sum(A[i][j] * v[j] for j in range(n)) for i in range(n)]
        norm = sum(x * x for x in w) ** 0.5
        if norm == 0:
            return 0.0, {k: 0.0 for k in idx}
        v = [x / norm for x in w]
        lam = norm
    tot = sum(v) or 1
    cent = {ip: round(v[i] / tot, 4) for ip, i in idx.items()}
    for ip, s in cent.items():
        c.execute("UPDATE nodes SET eig=? WHERE ip=?", (s, ip))
    return round(lam, 4), cent

EXPECTED = {"ssh", "https"}

def absences(c):
    """Eigenforensics: what should exist and doesn't."""
    out = []
    rows = c.execute("SELECT ip,tags,risk,eig FROM nodes").fetchall()
    if not rows:
        return out
    for ip, tags, risk, eig in rows:
        t = json.loads(tags)
        names = {x.split(":")[0] for x in t}
        if "http" in names and "https" not in names:
            out.append({"ip": ip, "absent": "tls", "why": "http exposed with no https sibling"})
        if "ssh" in names and "tls" not in names and "https" not in names:
            out.append({"ip": ip, "absent": "encrypted-alt", "why": "ssh is the only encrypted path"})
        if risk >= 40 and not any(x.startswith("https") for x in t):
            out.append({"ip": ip, "absent": "tls-on-high-risk", "why": "risk %d with no tls" % risk})
    deg = {ip: 0 for ip, _, _, _ in rows}
    for a, b, _ in c.execute("SELECT a,b,kind FROM edges").fetchall():
        deg[a] = deg.get(a, 0) + 1
        deg[b] = deg.get(b, 0) + 1
    for ip, d in deg.items():
        if d == 0:
            out.append({"ip": ip, "absent": "edges", "why": "isolated node, no observed peer"})
    return out

def predict(c, target):
    """If A->B->C and B goes dark, predict where C reappears."""
    peers = [r[0] for r in c.execute(
        "SELECT CASE WHEN a=? THEN b ELSE a END FROM edges WHERE a=? OR b=?", (target, target, target))]
    if not peers:
        return {"target": target, "prediction": None, "reason": "no known peers"}
    scores = {}
    for p in peers:
        for q in [r[0] for r in c.execute(
                "SELECT CASE WHEN a=? THEN b ELSE a END FROM edges WHERE (a=? OR b=?) AND a!=? AND b!=?",
                (p, p, p, target, target))]:
            if q != target:
                scores[q] = scores.get(q, 0) + 1
    ranked = sorted(scores.items(), key=lambda x: -x[1])[:5]
    return {"target": target, "via_peers": peers,
            "prediction": ranked[0][0] if ranked else None,
            "candidates": ranked,
            "method": "two-hop co-occurrence; peer continuity is a hypothesis, not proof"}

def homeostasis(c):
    rows = c.execute("SELECT ts,nodes,edges,dominant FROM samples ORDER BY ts DESC LIMIT 20").fetchall()
    if len(rows) < 4:
        return {"state": "insufficient-history", "n": len(rows)}
    ns = [r[1] for r in rows]
    mu = sum(ns) / len(ns)
    sd = (sum((x - mu) ** 2 for x in ns) / len(ns)) ** 0.5
    latest = ns[0]
    sigma = 0.0 if sd == 0 else abs(latest - mu) / sd
    return {"state": "ALERT" if sigma > 3.2 else "stable",
            "sigma": round(sigma, 2), "mean": round(mu, 1), "latest": latest}

def cycle():
    """One OODA pass: SENSE -> THINK -> PLAN -> ACT -> LEARN -> REFLECT."""
    c = db(); STATE["cycles"] += 1
    obs = sniffer_proc()
    seen = 0
    for ip, ports in obs.items():
        if not in_scope(ip):
            continue
        upsert(c, ip, ports); seen += 1
    lam, cent = eigen(c)
    n = c.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    e = c.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
    c.execute("INSERT INTO samples VALUES(?,?,?,?)", (now(), n, e, lam))
    c.commit()
    abs_ = absences(c)
    hom = homeostasis(c)
    STATE["alerts"] = ([{"kind": "complexity", **hom}] if hom.get("state") == "ALERT" else [])
    STATE["last"] = {"ts": now(), "observed": seen, "nodes": n, "edges": e,
                     "dominant_eigenvalue": lam, "absences": len(abs_), "homeostasis": hom}
    c.close()
    return STATE["last"]

def report(c):
    lam, cent = eigen(c)
    nodes = c.execute("SELECT ip,tags,risk,eig,first_seen,last_seen FROM nodes ORDER BY eig DESC").fetchall()
    lines = ["# EVEZ-TRACER report", "", "generated: %s" % now(),
             "scope: %s" % ", ".join(STATE["scope"] or ["(none)"]),
             "dominant eigenvalue: %s" % lam, "", "## Nodes by centrality", ""]
    for ip, tags, risk, eig, fs, ls in nodes[:40]:
        lines.append("- `%s` eig=%s risk=%s first=%s last=%s tags=%s" %
                     (ip, eig, risk, fs, ls, ",".join(json.loads(tags))[:80]))
    a = absences(c)
    lines += ["", "## Structural absences (%d)" % len(a), ""]
    for x in a[:40]:
        lines.append("- `%s` missing **%s** — %s" % (x["ip"], x["absent"], x["why"]))
    lines += ["", "## Homeostasis", "", json.dumps(homeostasis(c))]
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", action="append", default=[])
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--cycle", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--predict")
    ap.add_argument("--ingest")
    a = ap.parse_args()
    if a.scope:
        STATE["scope"] = a.scope
    else:
        STATE["scope"] = ["127.0.0.0/8", "::1/128"]
        try:
            h = socket.gethostbyname(socket.gethostname())
            if not h.startswith("127."):
                STATE["scope"].append(h + "/32")
        except Exception:
            pass
    if a.cycle:
        print(json.dumps(cycle(), indent=2)); return
    if a.report:
        print(report(db())); return
    if a.ingest:
        c = db(); n = 0
        for line in open(a.ingest):
            try:
                r = json.loads(line)
            except Exception:
                continue
            ip = r.get("ip") or r.get("src") or r.get("remote")
            if not ip:
                continue
            ports = r.get("ports") or []
            if not ports:
                p_ = r.get("port") or r.get("dport")
                ports = [int(p_)] if p_ else [0]
            upsert(c, ip, [int(x) for x in ports if str(x).isdigit()],
                   r.get("peer") or r.get("asn"))
            n += 1
        lam, cent = eigen(c); c.commit(); c.close()
        print(json.dumps({"ingested": n, "dominant_eigenvalue": lam}, indent=2)); return
    if a.predict:
        print(json.dumps(predict(db(), a.predict), indent=2)); return
    print("usage: --cycle | --report | --predict IP | --port N (serve)", file=sys.stderr)

if __name__ == "__main__":
    main()
