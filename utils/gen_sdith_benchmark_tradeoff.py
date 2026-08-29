#!/usr/bin/env python3
"""Regenerate the SDITH benchmark datasets and the standalone trade-off graph.

It runs the repo's `build/bench_signature_<CAT>` binaries, parses the median
signing / verification cycle counts and the key/signature sizes, and writes:

  * `sdith_current.json`             — the 12 current parameter sets
                                       (cat{1,3,5} x {fast,short} x {base, cipherpow})
  * `sdith_tradeoff.json`            — the full kappa = 5..12 trade-off, 6 curves:
                                       cat{1,3,5} x {shake-PoW, cipher-PoW}
  * `sdith_benchmark_tradeoff.html`  — a standalone page embedding both datasets

Everything lands in `docs/` unless --out-dir / --out say otherwise.

Extra datasets can be overlaid with `--extra-data file.json` (repeatable). Each
file holds either a bare list of points or `{"meta": {...}, "points": [...]}`,
with at least `variant`, `sign_median_mcycles`, `verify_median_mcycles`,
`signature_bytes` and `public_key_bytes` per point. Each file becomes one extra
scatter series, named after `meta.label` (default: the file stem), that the
legend shows / hides as a whole.

Usage:
  utils/gen_sdith_benchmark_tradeoff.py                 # build, run everything, regenerate
  utils/gen_sdith_benchmark_tradeoff.py --no-build      # skip cmake, just run existing binaries
  utils/gen_sdith_benchmark_tradeoff.py --no-bench      # only regenerate the HTML from existing JSONs
  utils/gen_sdith_benchmark_tradeoff.py --no-sweep      # skip the kappa sweep (keep the existing JSON)
  utils/gen_sdith_benchmark_tradeoff.py --only-sweep    # only re-measure the kappa sweep
  utils/gen_sdith_benchmark_tradeoff.py --extra-data other_box.json
  utils/gen_sdith_benchmark_tradeoff.py --build-dir build-debug --out-dir /tmp/graph
"""
import argparse, json, subprocess, sys, re, os, datetime, random, functools
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_OUT_DIR = os.path.join(ROOT, "docs")
HTML_NAME = "sdith_benchmark_tradeoff.html"
CURRENT_NAME = "sdith_current.json"
TRADEOFF_NAME = "sdith_tradeoff.json"
GENERATOR = "utils/gen_sdith_benchmark_tradeoff.py"

# (bench target category, display variant name, NIST security level)
CATEGORIES = [
    ("CAT1_FAST",  "sdith_cat1_fast",  1), ("CAT1_SHORT", "sdith_cat1_short", 1),
    ("CAT3_FAST",  "sdith_cat3_fast",  3), ("CAT3_SHORT", "sdith_cat3_short", 3),
    ("CAT5_FAST",  "sdith_cat5_fast",  5), ("CAT5_SHORT", "sdith_cat5_short", 5),
    ("CAT1_FAST_CIPHERPOW",  "sdith_cat1_fast_cipherpow",  1),
    ("CAT1_SHORT_CIPHERPOW", "sdith_cat1_short_cipherpow", 1),
    ("CAT3_FAST_CIPHERPOW",  "sdith_cat3_fast_cipherpow",  3),
    ("CAT3_SHORT_CIPHERPOW", "sdith_cat3_short_cipherpow", 3),
    ("CAT5_FAST_CIPHERPOW",  "sdith_cat5_fast_cipherpow",  5),
    ("CAT5_SHORT_CIPHERPOW", "sdith_cat5_short_cipherpow", 5),
]

# The kappa = 5..12 trade-off curves. Each one starts from a shipped CATx_SHORT
# parameter set (so rsd / mux / PoW-variant are inherited) and overrides
# kappa, tau, proofow_w and target_topen at run time.
# (base bench target, curve key, NIST security level, lambda, cipher-based PoW?)
SWEEP_BASES = [
    ("CAT1_SHORT",           "cat1",        1, 128, False),
    ("CAT1_SHORT_CIPHERPOW", "cat1-cipher", 1, 128, True),
    ("CAT3_SHORT",           "cat3",        3, 192, False),
    ("CAT3_SHORT_CIPHERPOW", "cat3-cipher", 3, 192, True),
    ("CAT5_SHORT",           "cat5",        5, 256, False),
    ("CAT5_SHORT_CIPHERPOW", "cat5-cipher", 5, 256, True),
]
SWEEP_KAPPAS = list(range(5, 13))
# cipher-PoW curves only: how many grinding bits we are willing to buy a tau back with.
# Per lambda, because the grinding cost is very asymmetric: 2^14 attempts cost ~0.6 Mcycles
# at cat1 (aes128) but ~5.5 Mcycles at cat3/cat5 (rijndael256 + shake256).
CIPHERPOW_MAX_W = {128: 14, 192: 12, 256: 12}
# target_topen is picked so that a random delta passes the topen check with this
# probability (i.e. the sibling-path grinding costs ~log2(1/p) extra bits on top
# of proofow_w). Matched to the order of magnitude used by the shipped sets.
TOPEN_ACCEPT_PROB = 0.2
TOPEN_SAMPLES = 8000
TOPEN_SEED = 20250817

# fields an --extra-data point must carry
EXTRA_REQUIRED = ("variant", "sign_median_mcycles", "verify_median_mcycles",
                  "signature_bytes", "public_key_bytes")


def sweep_kappa_tau_w(lam, kappa, cipherpow):
    """tau / proofow_w for one point of a trade-off curve (soundness: tau*kappa + w = lambda+2)."""
    tau = lam // kappa
    w = lam + 2 - tau * kappa
    # the cipher-based PoW is cheap enough that trading a VOLE repetition for
    # kappa more grinding bits is worth it, as long as we stay under the budget.
    # applied greedily: keep buying tau back while the budget allows.
    while cipherpow and w + kappa <= CIPHERPOW_MAX_W[lam]:
        tau -= 1
        w += kappa
    return tau, w


def estimate_topen(sorted_desc_leaves):
    """Python mirror of estimate_topen() in src/ggm.c: size of the sibling path."""
    b = deque(sorted_desc_leaves)
    size = 0
    while len(b) >= 2:
        first = b.popleft()
        if (first ^ b[0]) == 1:
            b.popleft()  # both children hidden: nothing to open
        else:
            size += 1
        b.append(first >> 1)
    node = b[0]
    while node != 1:
        size += 1
        node >>= 1
    return size


@functools.lru_cache(maxsize=None)
def pick_target_topen(tau, kappa, prob=TOPEN_ACCEPT_PROB, n=TOPEN_SAMPLES):
    """Monte-Carlo the topen distribution and return its `prob` quantile."""
    rnd = random.Random(TOPEN_SEED ^ (tau << 8) ^ kappa)
    randrange, num_deltas, start = rnd.randrange, 1 << kappa, tau << kappa
    samples = sorted(
        estimate_topen(sorted((randrange(num_deltas) * tau + k + start for k in range(tau)), reverse=True))
        for _ in range(n))
    return samples[int(n * prob)]


RE_SIGN = re.compile(r"^\s*sign_bytes\s*\.*\s*:\s*(\d+)")
RE_PKEY = re.compile(r"^\s*pkey_bytes\s*\.*\s*:\s*(\d+)")
# " 50%            0.002818     7.046204     0.002415     6.038538"
RE_MED = re.compile(r"^\s*50%\s+\S+\s+(\S+)\s+\S+\s+(\S+)")


def run_bench(build_dir, cat, overrides=()):
    binp = os.path.join(build_dir, f"bench_signature_{cat}")
    if not os.path.exists(binp):
        raise FileNotFoundError(
            f"missing {binp} — build it first (drop --no-build, or run cmake --build {build_dir})")
    out = subprocess.run([binp, "h", *overrides], capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0:
        raise RuntimeError(f"{binp} exited {out.returncode}\n{out.stderr[-2000:]}")
    sign = pk = sig = ver = None
    for line in out.stdout.splitlines():
        m = RE_SIGN.match(line);  sign = int(m.group(1)) if m else sign
        m = RE_PKEY.match(line);  pk = int(m.group(1)) if m else pk
        m = RE_MED.match(line)
        if m: sig, ver = float(m.group(1)), float(m.group(2))
    if None in (sign, pk, sig, ver):
        raise RuntimeError(f"parse failed for {cat}: sign={sign} pk={pk} sig={sig} ver={ver}")
    return sign, pk, sig, ver


def build_targets(build_dir):
    targets = sorted({f"bench_signature_{c}" for c, _, _ in CATEGORIES}
                     | {f"bench_signature_{b}" for b, _, _, _, _ in SWEEP_BASES})
    print(f"[build] cmake --build {build_dir} --target " + " ".join(targets))
    r = subprocess.run(["cmake", "--build", build_dir, "-j", "--target", *targets], cwd=ROOT)
    if r.returncode != 0:
        sys.exit("build failed")


def collect(build_dir):
    pts = []
    for cat, variant, lvl in CATEGORIES:
        sign, pk, sig_mcyc, ver_mcyc = run_bench(build_dir, cat)
        pts.append({
            "scheme": "current-SDITH",
            "variant": variant,
            "security_level": lvl,
            "sign_median_mcycles": round(sig_mcyc, 3),
            "verify_median_mcycles": round(ver_mcyc, 3),
            "signature_bytes": sign,
            "public_key_bytes": pk,
            "pk_plus_sig_bytes": sign + pk,
        })
        print(f"  {variant:28s} sign={sig_mcyc:8.3f}  verify={ver_mcyc:8.3f}  "
              f"sig={sign}  pk+sig={sign+pk}")
    return pts


def collect_sweep(build_dir):
    pts = []
    for base, curve, lvl, lam, cipherpow in SWEEP_BASES:
        for kappa in SWEEP_KAPPAS:
            tau, w = sweep_kappa_tau_w(lam, kappa, cipherpow)
            topen = pick_target_topen(tau, kappa)
            overrides = [f"kappa={kappa}", f"tau={tau}", f"proofow_w={w}", f"target_topen={topen}"]
            sign, pk, sig_mcyc, ver_mcyc = run_bench(build_dir, base, overrides)
            pts.append({
                "scheme": "sdith-tradeoff",
                "curve": curve,
                "variant": f"{curve}_k{kappa}",
                "security_level": lvl,
                "lambda": lam,
                "cipherpow": cipherpow,
                "kappa": kappa,
                "tau": tau,
                "proofow_w": w,
                "target_topen": topen,
                "sign_median_mcycles": round(sig_mcyc, 3),
                "verify_median_mcycles": round(ver_mcyc, 3),
                "signature_bytes": sign,
                "public_key_bytes": pk,
                "pk_plus_sig_bytes": sign + pk,
            })
            print(f"  {curve:12s} kappa={kappa:2d} tau={tau:3d} w={w:2d} topen={topen:3d}  "
                  f"sign={sig_mcyc:8.3f}  verify={ver_mcyc:8.3f}  pk+sig={sign+pk}")
    return pts


def write_current(path, pts):
    out = {
        "meta": {
            "source": "local benchmark (this repo)",
            "generator": GENERATOR,
            "retrieved": datetime.date.today().isoformat(),
            "statistic": "median (201 runs)",
            "scheme": "current-SDITH",
            "units": {"cycles": "million cycles", "sizes": "bytes"},
        },
        "points": pts,
    }
    json.dump(out, open(path, "w"), indent=2)
    print(f"[write] {path}  ({len(pts)} variants)")


def write_tradeoff(path, pts):
    out = {
        "meta": {
            "source": "local benchmark (this repo)",
            "generator": GENERATOR,
            "retrieved": datetime.date.today().isoformat(),
            "statistic": "median (201 runs)",
            "scheme": "sdith-tradeoff",
            "kappa_range": [SWEEP_KAPPAS[0], SWEEP_KAPPAS[-1]],
            "rule": "tau = floor(lambda/kappa); proofow_w = lambda+2-tau*kappa; "
                    "cipher-PoW only: while proofow_w+kappa <= max_w do tau -= 1, proofow_w += kappa "
                    f"(max_w per lambda: {CIPHERPOW_MAX_W}); "
                    f"target_topen = {TOPEN_ACCEPT_PROB} quantile of the topen distribution "
                    f"({TOPEN_SAMPLES} Monte-Carlo samples, seed {TOPEN_SEED})",
            "units": {"cycles": "million cycles", "sizes": "bytes"},
        },
        "points": pts,
    }
    json.dump(out, open(path, "w"), indent=2)
    print(f"[write] {path}  ({len(pts)} points)")


def load_extra(path):
    """One --extra-data file -> {"label": ..., "points": [...]} ready to embed."""
    raw = json.load(open(path))
    if isinstance(raw, list):
        meta, pts = {}, raw
    else:
        meta, pts = raw.get("meta", {}), raw.get("points", [])
    if not pts:
        sys.exit(f"{path}: no points")
    label = meta.get("label") or os.path.splitext(os.path.basename(path))[0]
    for i, p in enumerate(pts):
        missing = [k for k in EXTRA_REQUIRED if p.get(k) is None]
        if missing:
            sys.exit(f"{path}: point #{i} is missing {', '.join(missing)}")
        p.setdefault("pk_plus_sig_bytes", p["signature_bytes"] + p["public_key_bytes"])
    print(f"[extra] {path}  -> '{label}' ({len(pts)} points)")
    return {"label": label, "points": pts}


def write_html(html_path, current_json, tradeoff_json, extras, gendate):
    for p in (current_json, tradeoff_json):
        if not os.path.exists(p):
            sys.exit(f"missing {p} — re-measure it (drop --no-bench / --no-sweep / --only-sweep)")
    cur = open(current_json).read().strip()
    trd = open(tradeoff_json).read().strip()
    html = (HTML_TEMPLATE
            .replace("__CURRENT_JSON__", cur)
            .replace("__TRADEOFF_JSON__", trd)
            .replace("__EXTRA_JSON__", json.dumps(extras))
            .replace("__GENDATE__", gendate))
    open(html_path, "w").write(html)
    print(f"[write] {html_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                    help="where the JSON datasets and the page are written (default: docs/)")
    ap.add_argument("--out", default=None,
                    help=f"path of the generated page (default: <out-dir>/{HTML_NAME})")
    ap.add_argument("--extra-data", action="append", default=[], metavar="FILE",
                    help="overlay an external dataset as one extra series (repeatable)")
    ap.add_argument("--no-build", action="store_true", help="do not (re)build the bench targets")
    ap.add_argument("--no-bench", action="store_true", help="only regenerate HTML from existing JSONs")
    ap.add_argument("--no-sweep", action="store_true", help="do not re-measure the kappa trade-off curves")
    ap.add_argument("--only-sweep", action="store_true", help="only re-measure the kappa trade-off curves")
    args = ap.parse_args()
    bd = args.build_dir if os.path.isabs(args.build_dir) else os.path.join(ROOT, args.build_dir)
    out_dir = os.path.abspath(args.out_dir)
    html_path = os.path.abspath(args.out) if args.out else os.path.join(out_dir, HTML_NAME)
    current_json = os.path.join(out_dir, CURRENT_NAME)
    tradeoff_json = os.path.join(out_dir, TRADEOFF_NAME)
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.dirname(html_path), exist_ok=True)

    extras = [load_extra(p) for p in args.extra_data]

    if not args.no_bench:
        if not args.no_build:
            build_targets(bd)
        if not args.only_sweep:
            print(f"[bench] running {len(CATEGORIES)} SDITH variants from {bd} ...")
            write_current(current_json, collect(bd))
        if not args.no_sweep:
            n = len(SWEEP_BASES) * len(SWEEP_KAPPAS)
            print(f"[bench] running the kappa trade-off sweep ({n} points) from {bd} ...")
            write_tradeoff(tradeoff_json, collect_sweep(bd))
    write_html(html_path, current_json, tradeoff_json, extras,
               datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    print(f"done. open {html_path}")


HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SDITH — signing cost vs size</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
<style>
  .viz-root {
    --surface-1: #fcfcfb; --page: #f9f9f7;
    --text-primary: #0b0b0b; --text-secondary: #52514e; --muted: #898781;
    --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,0.10);
    --s-current: #eb6834;  /* slot 8 orange — the shipped parameter sets */
    --s-sweep: #b8860b;    /* slot 6 gold — the kappa trade-off curves */
    --s-extra-1: #2a78d6; --s-extra-2: #1baf7a; --s-extra-3: #9a5cd0; --s-extra-4: #c0392b;
    --link: #2a78d6;
    color-scheme: light;
  }
  .viz-root[data-theme="dark"] {
    --surface-1: #1a1a19; --page: #0d0d0d;
    --text-primary: #ffffff; --text-secondary: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
    --s-current: #d95926; --s-sweep: #dcab3c;
    --s-extra-1: #3987e5; --s-extra-2: #199e70; --s-extra-3: #a96fdc; --s-extra-4: #d1503f;
    --link: #3987e5;
    color-scheme: dark;
  }
  @media (prefers-color-scheme: dark) {
    .viz-root[data-theme="auto"] {
      --surface-1: #1a1a19; --page: #0d0d0d;
      --text-primary: #ffffff; --text-secondary: #c3c2b7; --muted: #898781;
      --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
      --s-current: #d95926; --s-sweep: #dcab3c;
      --s-extra-1: #3987e5; --s-extra-2: #199e70; --s-extra-3: #a96fdc; --s-extra-4: #d1503f;
      --link: #3987e5;
      color-scheme: dark;
    }
  }
  html,body { margin:0; }
  .viz-root { background: var(--page); color: var(--text-primary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif; min-height:100vh;
    padding:24px; box-sizing:border-box; }
  .card { max-width:1000px; margin:0 auto; background:var(--surface-1);
    border:1px solid var(--border); border-radius:12px; padding:20px 22px; }
  h1 { font-size:18px; margin:0 0 2px; font-weight:600; }
  .sub { font-size:12.5px; color:var(--text-secondary); margin:0 0 14px; line-height:1.45; }
  .sub a { color:var(--link); }
  .controls { display:flex; flex-wrap:wrap; gap:16px; align-items:center; margin-bottom:10px;
    font-size:13px; color:var(--text-secondary); }
  .controls fieldset { border:0; padding:0; margin:0; display:flex; gap:8px; align-items:center; }
  .seg { display:inline-flex; border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  .seg button { appearance:none; border:0; background:transparent; color:var(--text-secondary);
    font:inherit; padding:5px 11px; cursor:pointer; }
  .seg button[aria-pressed="true"] { background:var(--link); color:#fff; }
  .legend { display:flex; gap:14px; align-items:center; margin-left:auto; flex-wrap:wrap; }
  .legend .item { display:inline-flex; gap:7px; align-items:center; font-size:13px; color:var(--text-secondary);
    cursor:pointer; user-select:none; }
  .legend .item[aria-pressed="false"] { opacity:.35; }
  .legend .dot { width:11px; height:11px; border-radius:50%; }
  .legend .dash { width:26px; height:0; border-top-width:2.5px; }
  .legend .sep { width:1px; height:15px; background:var(--border); margin:0 2px; }
  .legend .grp { font-size:12px; color:var(--muted); }
  .legend .mini { appearance:none; border:1px solid var(--border); background:transparent;
    color:var(--text-secondary); font:inherit; font-size:11.5px; padding:2px 7px;
    border-radius:6px; cursor:pointer; }
  .legend .mini:hover { color:var(--text-primary); }
  svg { display:block; width:100%; height:auto; }
  .grid line { stroke:var(--grid); shape-rendering:crispEdges; }
  .grid path { stroke:none; }
  .axis path, .axis line { stroke:var(--axis); shape-rendering:crispEdges; }
  .axis text { fill:var(--muted); font-size:11px; }
  .axis-title { fill:var(--text-secondary); font-size:12.5px; font-weight:500; }
  .pt-label { fill:var(--text-secondary); font-size:9.5px; paint-order:stroke;
    stroke:var(--surface-1); stroke-width:3px; stroke-linejoin:round; }
  .dot { stroke:var(--surface-1); stroke-width:2px; cursor:pointer; }
  .curve { fill:none; stroke-width:1.8px; stroke-linecap:round; }
  .curve-label { fill:var(--text-secondary); font-size:9.5px; paint-order:stroke;
    stroke:var(--surface-1); stroke-width:3px; stroke-linejoin:round; }
  .tooltip { position:fixed; pointer-events:none; opacity:0; transition:opacity .08s;
    background:var(--surface-1); color:var(--text-primary); border:1px solid var(--border);
    border-radius:8px; padding:8px 10px; font-size:12px; box-shadow:0 6px 24px rgba(0,0,0,.18);
    max-width:270px; z-index:10; }
  .tooltip b { font-size:12.5px; }
  .tooltip .row { color:var(--text-secondary); display:flex; justify-content:space-between; gap:14px; }
  .tooltip .row span:last-child { color:var(--text-primary); font-variant-numeric:tabular-nums; }
  table { border-collapse:collapse; width:100%; font-size:12.5px; margin-top:6px; }
  th,td { text-align:right; padding:6px 8px; border-bottom:1px solid var(--border); font-variant-numeric:tabular-nums; }
  th:first-child,td:first-child,th:nth-child(2),td:nth-child(2) { text-align:left; font-variant-numeric:normal; }
  thead th { color:var(--muted); font-weight:600; }
  .swatch { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; }
  td.na { color:var(--muted); }
  .hidden { display:none; }
  .note { font-size:11.5px; color:var(--muted); margin-top:10px; }
</style>
</head>
<body>
<div class="viz-root" data-theme="auto">
  <div class="card">
    <h1>SDITH — signing cost vs size</h1>
    <p class="sub">y = median <span id="metric-word">signing</span> time (Mcycles, log) · x = public key + signature (bytes, linear).
      Measured locally from this repo (generated __GENDATE__).
      The dotted curves sweep κ = 5..12 for cat1/cat3/cat5, with τ = ⌊λ/κ⌋ and w = λ+2−τκ;
      dashed = cipher-based proof of work.</p>

    <div class="controls">
      <fieldset aria-label="Metric"><span>Metric</span>
        <div class="seg" id="seg-metric">
          <button data-metric="sign" aria-pressed="true">Sign</button>
          <button data-metric="verify" aria-pressed="false">Verify</button>
        </div></fieldset>
      <fieldset aria-label="View"><span>View</span>
        <div class="seg" id="seg-view">
          <button data-view="chart" aria-pressed="true">Chart</button>
          <button data-view="table" aria-pressed="false">Table</button>
        </div></fieldset>
      <fieldset aria-label="Theme"><span>Theme</span>
        <div class="seg" id="seg-theme">
          <button data-theme="auto" aria-pressed="true">Auto</button>
          <button data-theme="light" aria-pressed="false">Light</button>
          <button data-theme="dark" aria-pressed="false">Dark</button>
        </div></fieldset>
      <div class="legend" id="legend"></div>
    </div>

    <div id="chart-view">
      <svg id="chart" viewBox="0 0 980 560" role="img" aria-label="median cycles vs size"></svg>
    </div>
    <div id="table-view" class="hidden"></div>
    <p class="note" id="note"></p>
  </div>
</div>
<div class="tooltip" id="tt"></div>

<script id="embedded-current" type="application/json">__CURRENT_JSON__</script>
<script id="embedded-tradeoff" type="application/json">__TRADEOFF_JSON__</script>
<script id="embedded-extra" type="application/json">__EXTRA_JSON__</script>
<script>
const root = document.querySelector('.viz-root');
const tt = document.getElementById('tt');
const CUR = JSON.parse(document.getElementById('embedded-current').textContent);
const TRD = JSON.parse(document.getElementById('embedded-tradeoff').textContent);
// each --extra-data file is one series: {label, points}. Its legend entry shows
// / hides the whole file at once.
const EXTRA = JSON.parse(document.getElementById('embedded-extra').textContent);

// scatter series (one marker per variant)
const SERIES = [{ key: 'current-SDITH', varname: '--s-current' }].concat(
  EXTRA.map((e, i) => ({ key: e.label, varname: `--s-extra-${i % 4 + 1}`, isExtra: true })));
// trade-off curves: each one toggles on its own, but only the PoW variant changes
// the style — cat1 / cat3 / cat5 are far enough apart to stay unambiguous.
const CURVE_STYLE = { shake: { dash: '2 4', filled: true }, cipher: { dash: '9 5', filled: false } };
// derived from the data, so the legend always matches whatever the JSON holds
const CURVES = (() => {
  const defs = new Map();
  for (const p of TRD.points) {
    if (defs.has(p.curve)) continue;
    defs.set(p.curve, { key: p.curve, varname: '--s-sweep', isCurve: true,
                        ...CURVE_STYLE[p.cipherpow ? 'cipher' : 'shake'] });
  }
  return [...defs.values()];
})();
const defOf = key => SERIES.concat(CURVES).find(x => x.key === key);
const styleOf = key => defOf(key);

let state = { metric: 'sign', view: 'chart', off: new Set() };

const SCATTER = CUR.points.map(p => ({ ...p, series: 'current-SDITH' })).concat(
  ...EXTRA.map(e => e.points.map(p => ({ ...p, series: e.label }))));
const CURVE_PTS = TRD.points.map(p => ({ ...p, series: p.curve }));
const ALL = SCATTER.concat(CURVE_PTS);

document.getElementById('note').textContent =
  `${CUR.points.length} current variants + ${TRD.points.length} trade-off points`
  + EXTRA.map(e => ` + ${e.points.length} from '${e.label}'`).join('')
  + '. ' + (TRD.meta && TRD.meta.rule ? TRD.meta.rule : '');

const cssvar = n => getComputedStyle(root).getPropertyValue(n).trim();
const colorForSeries = s => cssvar(defOf(s).varname);
const yval = d => state.metric === 'sign' ? d.sign_median_mcycles : d.verify_median_mcycles;
const shortName = d => d.variant.replace(/^sdith_/, '');
const fmtInt = d3.format(',');

function buildLegend() {
  const L = d3.select('#legend'); L.selectAll('*').remove();
  const toggle = key => { if (state.off.has(key)) state.off.delete(key); else state.off.add(key);
    buildLegend(); render(); };
  const item = key => L.append('span').attr('class','item').attr('role','button')
    .attr('aria-pressed', state.off.has(key) ? 'false' : 'true')
    .attr('title', 'click to show / hide')
    .on('click', () => toggle(key));
  SERIES.forEach(s => {
    const it = item(s.key);
    it.append('span').attr('class','dot').style('background', colorForSeries(s.key));
    it.append('span').text(s.key);
  });

  if (!CURVES.length) return;
  L.append('span').attr('class','sep');
  L.append('span').attr('class','grp').text('κ sweep');
  CURVES.forEach(c => {
    const it = item(c.key);
    it.append('span').attr('class','dash')
      .style('border-top-style', c.filled ? 'dotted' : 'dashed')
      .style('border-top-color', colorForSeries(c.key));
    it.append('span').text(c.key);
  });
  // bulk show / hide for the whole sweep group
  const setAll = off => { CURVES.forEach(c => off ? state.off.add(c.key) : state.off.delete(c.key));
    buildLegend(); render(); };
  L.append('button').attr('class','mini').text('all').on('click', () => setAll(false));
  L.append('button').attr('class','mini').text('none').on('click', () => setAll(true));
}

function activePoints() { return ALL.filter(d => !state.off.has(d.series)); }

function render() {
  document.getElementById('metric-word').textContent = state.metric === 'sign' ? 'signing' : 'verification';
  document.getElementById('chart-view').classList.toggle('hidden', state.view !== 'chart');
  document.getElementById('table-view').classList.toggle('hidden', state.view !== 'table');
  if (state.view === 'chart') drawChart(); else drawTable();
}

function drawChart() {
  const pts = activePoints();
  const svg = d3.select('#chart'); svg.selectAll('*').remove();
  const W = 980, H = 560, m = { t: 14, r: 20, b: 52, l: 64 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const g = svg.append('g').attr('transform', `translate(${m.l},${m.t})`);
  if (!pts.length) { g.append('text').attr('class','axis-title').attr('x',iw/2).attr('y',ih/2)
    .attr('text-anchor','middle').text('no series selected'); return; }

  const x = d3.scaleLinear().domain([0, d3.max(pts, d => d.pk_plus_sig_bytes) * 1.06]).range([0, iw]).nice();
  const y = d3.scaleLog().domain([d3.min(pts, yval) * 0.8, d3.max(pts, yval) * 1.25]).range([ih, 0]);
  const yTicks = [0.5,1,2,5,10,20,50,100,200,500].filter(v => v >= y.domain()[0] && v <= y.domain()[1]);

  g.append('g').attr('class','grid').call(d3.axisLeft(y).tickValues(yTicks).tickSize(-iw).tickFormat(''));
  g.append('g').attr('class','grid').attr('transform',`translate(0,${ih})`)
    .call(d3.axisBottom(x).tickSize(-ih).tickFormat(''));
  g.append('g').attr('class','axis').attr('transform',`translate(0,${ih})`)
    .call(d3.axisBottom(x).ticks(8).tickFormat(d3.format(',')));
  g.append('g').attr('class','axis').call(d3.axisLeft(y).tickValues(yTicks).tickFormat(d3.format('~g')));

  g.append('text').attr('class','axis-title').attr('x', iw/2).attr('y', ih + 42)
    .attr('text-anchor','middle').text('public key + signature (bytes)');
  g.append('text').attr('class','axis-title').attr('transform','rotate(-90)')
    .attr('x', -ih/2).attr('y', -48).attr('text-anchor','middle')
    .text('median ' + (state.metric==='sign'?'signing':'verification') + ' (Mcycles, log)');

  // one dotted path per (category, PoW variant), ordered along the kappa sweep
  const line = d3.line().x(d => x(d.pk_plus_sig_bytes)).y(d => y(yval(d)));
  for (const [curveKey, cp] of d3.group(pts.filter(d => d.curve), d => d.curve)) {
    const ordered = cp.slice().sort((a, b) => a.kappa - b.kappa);
    g.append('path').attr('class','curve').attr('d', line(ordered))
      .attr('stroke', colorForSeries(ordered[0].series))
      .attr('stroke-dasharray', styleOf(ordered[0].series).dash);
    // name the low-kappa (top-right) end of each curve, flipping near the right edge
    const head = ordered[0], hx = x(head.pk_plus_sig_bytes), flip = hx > iw - 110;
    g.append('text').attr('class','curve-label')
      .attr('x', hx + (flip ? -8 : 8)).attr('y', y(yval(head)) + 13)
      .attr('text-anchor', flip ? 'end' : 'start')
      .text(`${curveKey} κ=${head.kappa}..${ordered[ordered.length-1].kappa}`);
  }

  const scatter = pts.filter(d => !d.curve);
  const markers = pts.filter(d => d.curve);
  g.selectAll('circle.dot').data(scatter).join('circle')
    .attr('class','dot').attr('r',6)
    .attr('cx', d => x(d.pk_plus_sig_bytes)).attr('cy', d => y(yval(d)))
    .attr('fill', d => colorForSeries(d.series))
    .on('mousemove', showTip).on('mouseleave', hideTip);

  // curve markers: filled for the shake PoW, hollow for the cipher PoW
  g.selectAll('circle.mark').data(markers).join('circle')
    .attr('class','mark').attr('r',3.4)
    .attr('cx', d => x(d.pk_plus_sig_bytes)).attr('cy', d => y(yval(d)))
    .attr('fill', d => styleOf(d.series).filled ? colorForSeries(d.series) : cssvar('--surface-1'))
    .attr('stroke', d => colorForSeries(d.series)).attr('stroke-width', 1.6)
    .style('cursor','pointer')
    .on('mousemove', showTip).on('mouseleave', hideTip);

  g.selectAll('text.pt-label').data(scatter).join('text').attr('class','pt-label')
    .attr('x', d => x(d.pk_plus_sig_bytes) + (x(d.pk_plus_sig_bytes) > iw-92 ? -9 : 9))
    .attr('y', d => y(yval(d)) + 3)
    .attr('text-anchor', d => x(d.pk_plus_sig_bytes) > iw-92 ? 'end' : 'start')
    .text(shortName);
}

function showTip(event, d) {
  tt.innerHTML = `<b>${d.variant}</b> · ${d.series}`
    + (d.security_level ? ` · L${d.security_level}` : '')
    + (d.curve ? `<div class="row"><span>κ / τ / w / topen</span>`
        + `<span>${d.kappa} / ${d.tau} / ${d.proofow_w} / ${d.target_topen}</span></div>` : '')
    + `<div class="row"><span>sign</span><span>${d.sign_median_mcycles} Mcyc</span></div>`
    + `<div class="row"><span>verify</span><span>${d.verify_median_mcycles} Mcyc</span></div>`
    + `<div class="row"><span>signature</span><span>${fmtInt(d.signature_bytes)} B</span></div>`
    + `<div class="row"><span>public key</span><span>${fmtInt(d.public_key_bytes)} B</span></div>`
    + `<div class="row"><span>pk + sig</span><span>${fmtInt(d.pk_plus_sig_bytes)} B</span></div>`;
  tt.style.opacity = 1;
  tt.style.left = Math.min(event.clientX + 14, window.innerWidth - tt.offsetWidth - 8) + 'px';
  tt.style.top = (event.clientY + 14) + 'px';
}
function hideTip() { tt.style.opacity = 0; }

function drawTable() {
  const cols = [['series','Series'],['variant','Variant'],['security_level','Lvl'],
    ['kappa','κ'],['tau','τ'],['proofow_w','w'],['target_topen','topen'],
    ['sign_median_mcycles','Sign (Mcyc)'],['verify_median_mcycles','Verify (Mcyc)'],
    ['signature_bytes','Sig (B)'],['public_key_bytes','PK (B)'],['pk_plus_sig_bytes','PK+Sig (B)']];
  const rows = activePoints().slice().sort((a,b) =>
    a.series.localeCompare(b.series) || a.variant.localeCompare(b.variant)
    || a.pk_plus_sig_bytes - b.pk_plus_sig_bytes);
  let h = '<table><thead><tr>' + cols.map(c=>`<th>${c[1]}</th>`).join('') + '</tr></thead><tbody>';
  for (const d of rows) {
    h += '<tr>' + cols.map(([k]) => {
      if (k==='series') return `<td><span class="swatch" style="background:${colorForSeries(d.series)}"></span>${d[k]}</td>`;
      const v = d[k];
      if (v === undefined) return '<td class="na">·</td>';   // scatter rows have no sweep params
      return `<td>${typeof v==='number' && k.endsWith('bytes') ? fmtInt(v) : v}</td>`;
    }).join('') + '</tr>';
  }
  document.getElementById('table-view').innerHTML = h + '</tbody></table>';
}

function wireSeg(id, key, cb) {
  document.querySelectorAll(`#${id} button`).forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll(`#${id} button`).forEach(x => x.setAttribute('aria-pressed','false'));
    b.setAttribute('aria-pressed','true'); cb(b.dataset[key]);
  }));
}
wireSeg('seg-metric','metric', v => { state.metric = v; render(); });
wireSeg('seg-view','view', v => { state.view = v; render(); });
wireSeg('seg-theme','theme', v => { root.setAttribute('data-theme', v); buildLegend(); if (state.view==='chart') drawChart(); });
window.addEventListener('resize', () => { if (state.view==='chart') drawChart(); });
buildLegend(); render();
</script>
</body>
</html>
'''

if __name__ == "__main__":
    main()
