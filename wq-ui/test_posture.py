"""Tests for wq_posture (the shield score). No Qt, no firejail."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_core as core  # noqa: E402
import wq_posture as P  # noqa: E402

HOME = "/home/tester"


def game(conf=None, runner="wine"):
    g = core.Game("T", Path("/nonexistent/T"), dict(conf or {}))
    if runner == "native":
        g.conf["RUNNER"] = ["native"]
    return g


def post(conf=None, defaults=None, runner="wine"):
    return P.posture_for_game(game(conf, runner), defaults or {}, home=HOME)


# stock defaults: strong but not perfect (host display, webcams, game folder writable...)
stock = post()
print("stock:", stock.score, stock.grade, [f.key for f in stock.findings])
assert 60 <= stock.score < 75 and stock.status == "warn", stock    # stock Wine has several compatibility relaxations
assert "FJ_PRIVATE_HOME" not in [f.key for f in stock.findings]
assert "FJ_XEPHYR" in [f.key for f in stock.findings]            # host X11 is the biggest stock gap
# Wine needs these off, but off is still weaker: every runner is charged, so Relax / presets show up in the score
for k in ("FJ_RESTRICT_NS", "FJ_MEMFD", "FJ_MDWX"):
    assert k in [f.key for f in stock.findings], k
assert "FJ_RESTRICT_NS" not in [f.key for f in post(runner="native").findings]   # native defaults to on
assert "FJ_RESTRICT_NS" in [f.key for f in post({"FJ_RESTRICT_NS": ["0"]}, runner="native").findings]
assert "FJ_RESTRICT_NS" in [f.key for f in post({"FJ_RESTRICT_NS": ["0"]}).findings]
assert "FJ_RESTRICT_NS" not in [f.key for f in post({"FJ_RESTRICT_NS": ["1"]}).findings]

# the Strict preset (everything on, no network) is a perfect score
strict = {k: ["1"] for k, v in core.PRESETS["Strict"].items() if v}
strict.update({k: ["0"] for k, v in core.PRESETS["Strict"].items() if not v})
strict["FJ_XEPHYR"] = ["1"]
s = post(strict)
print("strict:", s.score, [f.key for f in s.findings])
assert s.score == 100 and s.grade == "A" and not s.findings and s.headline() == "Every protection is on"

# each switch costs what the table says, and findings come out worst first
off = post({"FJ_PRIVATE_HOME": ["0"]})
assert off.score == stock.score - 14
assert [f.penalty for f in off.findings] == sorted((f.penalty for f in off.findings), reverse=True)

# network modes
base = post(strict).score
assert post({**strict, "FJ_NET": ["1"]}).score == base - 6
assert post({**strict, "FJ_NET": ["1"], "FJ_NET_LEARN": ["1"]}).score == base - 30
op = post({**strict, "FJ_NET": ["1"], "FJ_NET_OPEN": ["1"]})
assert op.score == base - 45 and op.status == "warn" and op.findings[0].key == "FJ_NET"
assert post({**strict, "FJ_NET": ["0"], "FJ_NET_OPEN": ["1"]}).score == base   # open but network off: nothing
assert post({**strict, "FJ_NET": ["1"], "FJ_NET_DNS": ["1"]}).score == base - 6 - 3
assert post({**strict, "FJ_NET": ["1"], "FJ_NET_DNS": ["1"], "FJ_NET_OPEN": ["1"]}).score == base - 45 - 3
# wide allow-list entries only matter in filtered mode
wide = {**strict, "FJ_NET": ["1"], "FJ_NET_ALLOW": ["tcp:10.0.0.0/8:443", "udp:1.2.3.4:*", "tcp:1.2.3.4:443"]}
w = post(wide)
assert w.score == base - 6 - 8 and "FJ_NET_ALLOW" in [f.key for f in w.findings]
assert "FJ_NET_ALLOW" not in [f.key for f in post({**wide, "FJ_NET_OPEN": ["1"]}).findings]

# whitelists
rw = post({**strict, "FJ_WL_RW": ["/mnt/saves", "/mnt/more"]})
assert rw.score == base - 10
assert post({**strict, "FJ_WL_RW": [f"/mnt/s{i}" for i in range(9)]}).score == base - 15      # capped
for p in (HOME, "/home", "/", HOME + "/"):
    h = post({**strict, "FJ_WL_RW": [p]})
    assert h.score == base - 25 and h.findings[0].severity == "bad", p
assert post({**strict, "FJ_WL_RW": [HOME + "/Games"]}).score == base - 5      # a subfolder is not the whole home
assert post({**strict, "FJ_WL_RO": ["/mnt/assets"]}).score == base - 1
assert post({**strict, "FJ_WL_RO": [HOME]}).score == base - 10
assert post({**strict, "FJ_WL_RW": ["relative/path"]}).score == base - 5       # junk still counts as an entry

# game.conf beats the defaults file, and an empty KEY= line means "none"
d = {"FJ_WL_RW": ["/mnt/from-defaults"]}
assert post(strict, d).score == base - 5
assert post({**strict, "FJ_WL_RW": [""]}, d).score == base
assert post({**strict, "FJ_NET": ["0"]}, {"FJ_NET": ["1"]}).score == base        # game overrides default

# hooks run outside the sandbox
assert post({**strict, "FJ_HOOK_PRE": ["/opt/x.sh"], "FJ_HOOK_POST": ["/opt/y.sh"]}).score == base - 12
assert post({**strict, "FJ_HOOK_PRE": [""]}).score == base
dh = post(strict, {"FJ_HOOK_PRE": ["/opt/x.sh"]})                               # defaults never carry hooks
assert dh.score == base

# memfd_create and write+execute memory: charged for every runner
nat_strict = post(strict, runner="native").score
assert nat_strict == 100
assert post({**strict, "FJ_MEMFD": ["0"]}, runner="native").score == 98
assert post({**strict, "FJ_MDWX": ["0"]}, runner="native").score == 97
assert post({**strict, "FJ_MEMFD": ["0"], "FJ_MDWX": ["0"]}, runner="native").score == 95
assert post({**strict, "FJ_MEMFD": ["0"], "FJ_MDWX": ["0"]}).score == 95         # Wine pays the same as native
assert post({**strict, "FJ_NOTV": ["0"], "FJ_NODVD": ["0"]}).score == 98          # every relaxed switch costs something
# the score and the "relaxed" badge agree: every setting weaker than Strict is charged
for key in core.PRESETS["Strict"]:
    if key in ("FJ_NET", "FJ_NET_OPEN", "FJ_NET_LEARN") or key not in core.ALL_BOOLS:
        continue
    want = core.PRESETS["Strict"][key]
    relaxed = post({**strict, key: ["0" if want else "1"]}, runner="wine")
    assert relaxed.score < 100, (key, relaxed.score)
nd = post({**strict, "FJ_MDWX": ["0"]}, runner="native")
assert nd.findings[0].key == "FJ_MDWX" and "JIT" not in nd.findings[0].title and nd.findings[0].severity == "info"
assert post({"FJ_MDWX": ["0"]}, runner="native").score == post(runner="native").score      # default is off: stock native already pays it
assert post({"FJ_MDWX": ["1"], "FJ_MEMFD": ["1"]}, runner="native").score == post(runner="native").score + 5

# floor, grades, colours
worst = post({k: ["0"] for k in core.ALL_BOOLS} | {"FJ_NET": ["1"], "FJ_NET_OPEN": ["1"],
                                                    "FJ_WL_RW": [HOME], "FJ_HOOK_PRE": ["/x"]})
print("worst:", worst.score, worst.grade)
assert worst.score == 0 and worst.grade == "F" and worst.status == "bad"
for score_, grade in ((100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (55, "C"), (54, "D"), (35, "D"), (34, "F")):
    assert next(g for floor, g in P.GRADES if score_ >= floor) == grade, score_

# panel states: None (games differ) counts as relaxed and says so
inp = P.PostureInputs(flags={**{k: True for k, *_ in P.PENALTY}, "FJ_PRIVATE_HOME": None, "FJ_NET": False},
                      runner="wine", home=HOME)
r = P.score(inp)
f = next(x for x in r.findings if x.key == "FJ_PRIVATE_HOME")
assert f.penalty == 14 and "disagree" in f.detail
assert P.net_mode_of({"FJ_NET": None}) == "filtered" and P.net_mode_of({}) == "off"
assert P.net_mode_of({"FJ_NET": True, "FJ_NET_OPEN": None}) == "filtered"

# tooltip is readable and honest
tip = post({"FJ_PRIVATE_HOME": ["0"], "FJ_SECCOMP": ["0"]}).tooltip("T", limit=2)
assert tip.startswith("T: shield ") and "-14" in tip and "more" in tip and "not a safety guarantee" in tip

# every key the scorer reads exists in wq_core, so a renamed option can't silently stop counting
for key, *_ in P.PENALTY:
    assert key in core.ALL_BOOLS, key

print("posture: ok")
