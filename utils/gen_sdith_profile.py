#!/usr/bin/env python3
"""Profile the 12 current SDITH parameter sets by REUSING build/bench_signature_<CAT>.

For each parameter set it produces, under docs/profile/ (or --out-dir):
  * flame_<CAT>_sign.html    interactive flame graph of sdith_sign   (perf, dwarf stacks)
  * flame_<CAT>_verify.html  interactive flame graph of sdith_verify (perf, dwarf stacks)
  * callgrind.out.<CAT>      valgrind callgrind (--cache-sim=yes --branch-sim=yes)
  * index.html               links + a callgrind top-functions summary

How the flame graphs are split without a custom binary: `bench_signature_<CAT> h`
runs 201 signatures then 201 verifications. We record the whole run with
`perf --call-graph dwarf`, then keep only the samples whose stack contains
`sdith_sign` (-> sign graph) or `sdith_verify` (-> verify graph), trimming each
stack to start at that frame. Keygen / one-shot instrumented blocks are dropped.

perf note: this box has no hardware PMU (AWS), so we sample the software
`task-clock` event; -O3 binaries need `--call-graph dwarf` to unwind.

Usage:
  utils/gen_sdith_profile.py                       # perf + callgrind for all 12
  utils/gen_sdith_profile.py --only perf
  utils/gen_sdith_profile.py --only callgrind
  utils/gen_sdith_profile.py --params CAT1_FAST,CAT5_SHORT
  utils/gen_sdith_profile.py --freq 1999 --build-dir build --out-dir /tmp/profile
"""
import argparse, os, re, subprocess, json, html, shutil, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_OUT = os.path.join(ROOT, "docs", "profile")

CATEGORIES = [
    "CAT1_FAST", "CAT1_SHORT", "CAT3_FAST", "CAT3_SHORT", "CAT5_FAST", "CAT5_SHORT",
    "CAT1_FAST_CIPHERPOW", "CAT1_SHORT_CIPHERPOW", "CAT3_FAST_CIPHERPOW",
    "CAT3_SHORT_CIPHERPOW", "CAT5_FAST_CIPHERPOW", "CAT5_SHORT_CIPHERPOW",
]

# ----------------------------- perf / flame graphs ---------------------------

def perf_record(binpath, data_path, freq):
    cmd = ["perf", "record", "--call-graph", "dwarf,8192", "-e", "task-clock",
           "-F", str(freq), "-o", data_path, "--", binpath, "h"]
    subprocess.run(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def parse_folded(data_path):
    """Return (sign_folded, verify_folded): dict 'root;...;leaf' -> sample count."""
    txt = subprocess.run(["perf", "script", "-i", data_path, "--no-inline"],
                         cwd=ROOT, capture_output=True, text=True).stdout
    sign, verify = {}, {}
    for block in txt.split("\n\n"):
        lines = block.splitlines()
        frames = []  # leaf-first
        for ln in lines:
            m = re.match(r"^\s+[0-9a-fA-F]+\s+(.+)$", ln)
            if not m:
                continue
            rest = re.sub(r"\s+\(.*\)\s*$", "", m.group(1))     # drop " (module)"/"(inlined)"
            sym = rest.split("+0x")[0].strip()
            if not sym or sym == "[unknown]":
                sym = "[unknown]"
            frames.append(sym)
        if not frames:
            continue
        for anchor, acc in (("sdith_sign", sign), ("sdith_verify", verify)):
            try:
                idx = frames.index(anchor)
            except ValueError:
                continue
            stack = list(reversed(frames[:idx + 1]))            # root(anchor) .. leaf
            acc[";".join(stack)] = acc.get(";".join(stack), 0) + 1
            break
    return sign, verify


def folded_to_tree(folded, root_name):
    root = {"n": root_name, "v": 0, "c": {}}
    for path, cnt in folded.items():
        frames = path.split(";")
        root["v"] += cnt
        node = root
        for f in frames[1:]:
            ch = node["c"].get(f)
            if ch is None:
                ch = {"n": f, "v": 0, "c": {}}
                node["c"][f] = ch
            ch["v"] += cnt
            node = ch
    def finish(n):
        kids = sorted(n["c"].values(), key=lambda k: -k["v"])
        return {"n": n["n"], "v": n["v"], "c": [finish(k) for k in kids]}
    return finish(root)


def write_flame(tree, title, subtitle, path):
    payload = json.dumps(tree, separators=(",", ":"))
    doc = (FLAME_TEMPLATE
           .replace("__TITLE__", html.escape(title))
           .replace("__SUBTITLE__", html.escape(subtitle))
           .replace("__TOTAL__", str(tree["v"]))
           .replace("__TREE_JSON__", payload))
    open(path, "w").write(doc)


def do_perf(cat, build_dir, out_dir, freq):
    binp = os.path.join(build_dir, f"bench_signature_{cat}")
    if not os.path.exists(binp):
        print(f"  [skip perf] missing {binp}"); return None
    data = os.path.join(out_dir, f"perf_{cat}.data")
    print(f"  [perf] recording {cat} (freq={freq}) ...", flush=True)
    perf_record(binp, data, freq)
    sign, verify = parse_folded(data)
    os.remove(data)
    ns, nv = sum(sign.values()), sum(verify.values())
    write_flame(folded_to_tree(sign, "sdith_sign"),
                f"{cat} — signature", f"perf task-clock, {ns} samples",
                os.path.join(out_dir, f"flame_{cat}_sign.html"))
    write_flame(folded_to_tree(verify, "sdith_verify"),
                f"{cat} — verification", f"perf task-clock, {nv} samples",
                os.path.join(out_dir, f"flame_{cat}_verify.html"))
    print(f"    sign={ns} samples, verify={nv} samples", flush=True)
    return (ns, nv)


# ----------------------------- callgrind -------------------------------------

def do_callgrind(cat, build_dir, out_dir):
    binp = os.path.join(build_dir, f"bench_signature_{cat}")
    if not os.path.exists(binp):
        print(f"  [skip callgrind] missing {binp}"); return None
    outf = os.path.join(out_dir, f"callgrind.out.{cat}")
    print(f"  [callgrind] {cat} ...", flush=True)
    subprocess.run(["valgrind", "--tool=callgrind", "--cache-sim=yes", "--branch-sim=yes",
                    f"--callgrind-out-file={outf}", binp],
                   cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    # top-functions summary (self inclusive Ir) for the index
    summ = subprocess.run(["callgrind_annotate", "--threshold=90", "--auto=no", outf],
                          capture_output=True, text=True).stdout
    return outf, summ


def summary_top(summ, n=15):
    lines = summ.splitlines()
    out, started = [], False
    for ln in lines:
        if re.match(r"^\s*Ir\s", ln):
            started = True
        if started:
            out.append(ln)
        if started and len(out) > n:
            break
    return "\n".join(out)


# ----------------------------- index -----------------------------------------

def write_index(results, out_dir):
    rows = []
    for cat in CATEGORIES:
        r = results.get(cat, {})
        sign = f'flame_{cat}_sign.html' if r.get("sign_html") else None
        ver = f'flame_{cat}_verify.html' if r.get("sign_html") else None
        cg = f'callgrind.out.{cat}' if r.get("callgrind") else None
        links = []
        if sign: links.append(f'<a href="{sign}">sign flame</a>')
        if ver: links.append(f'<a href="{ver}">verify flame</a>')
        if cg: links.append(f'<a href="{cg}" download>callgrind.out</a>')
        summ = r.get("summary", "")
        rows.append(f'<tr><td><b>{cat}</b></td><td>{" · ".join(links) or "—"}</td></tr>'
                    + (f'<tr><td colspan="2"><details><summary>callgrind top functions</summary>'
                       f'<pre>{html.escape(summ)}</pre></details></td></tr>' if summ else ""))
    doc = INDEX_TEMPLATE.replace("__ROWS__", "\n".join(rows)).replace(
        "__GENDATE__", datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    open(os.path.join(out_dir, "index.html"), "w").write(doc)
    print(f"[write] {os.path.join(out_dir,'index.html')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--out-dir", default=DEFAULT_OUT,
                    help="where the flame graphs, callgrind dumps and index land (default: docs/profile/)")
    ap.add_argument("--freq", type=int, default=1999)
    ap.add_argument("--only", choices=["perf", "callgrind"], default=None)
    ap.add_argument("--params", default=None, help="comma list of CAT ids (default all 12)")
    args = ap.parse_args()
    bd = args.build_dir if os.path.isabs(args.build_dir) else os.path.join(ROOT, args.build_dir)
    out_dir = os.path.abspath(args.out_dir)
    cats = args.params.split(",") if args.params else CATEGORIES
    os.makedirs(out_dir, exist_ok=True)
    for tool in ("perf", "valgrind", "callgrind_annotate"):
        if not shutil.which(tool):
            print(f"warning: {tool} not found in PATH")

    results = {}
    for cat in cats:
        print(f"== {cat} ==", flush=True)
        r = {}
        if args.only in (None, "perf"):
            res = do_perf(cat, bd, out_dir, args.freq)
            if res: r["sign_html"] = True
        if args.only in (None, "callgrind"):
            res = do_callgrind(cat, bd, out_dir)
            if res:
                r["callgrind"] = res[0]
                r["summary"] = summary_top(res[1])
        results[cat] = r
    write_index(results, out_dir)
    print(f"done. open {os.path.join(out_dir, 'index.html')}")


# ----------------------------- templates -------------------------------------

FLAME_TEMPLATE = r'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>__TITLE__ — flame graph</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; font-family: system-ui,-apple-system,"Segoe UI",sans-serif;
    background:#f9f9f7; color:#0b0b0b; }
  @media (prefers-color-scheme: dark){ body{ background:#0d0d0d; color:#fff; } .bar{ background:#1a1a19; } }
  .wrap { max-width:1240px; margin:0 auto; padding:16px 18px; }
  h1 { font-size:16px; margin:0 0 2px; }
  .sub { font-size:12px; color:#777; margin:0 0 10px; }
  .bar { position:sticky; top:0; background:#fcfcfb; padding:8px 0; display:flex; gap:10px; align-items:center; }
  input[type=search]{ font:inherit; padding:4px 8px; border:1px solid rgba(128,128,128,.4);
    border-radius:6px; background:transparent; color:inherit; width:240px; }
  button { font:inherit; padding:4px 10px; border:1px solid rgba(128,128,128,.4); border-radius:6px;
    background:transparent; color:inherit; cursor:pointer; }
  #crumb { font-size:12px; color:#777; }
  svg { width:100%; display:block; }
  text { pointer-events:none; font-family: inherit; }
  .tt { position:fixed; opacity:0; pointer-events:none; background:#fcfcfb; color:#0b0b0b;
    border:1px solid rgba(0,0,0,.15); border-radius:6px; padding:6px 9px; font-size:12px;
    box-shadow:0 6px 24px rgba(0,0,0,.2); z-index:9; max-width:520px; word-break:break-all; }
  @media (prefers-color-scheme: dark){ .bar{background:#1a1a19;} .tt{background:#1a1a19;color:#fff;border-color:rgba(255,255,255,.2);} }
</style></head><body><div class="wrap">
  <h1>__TITLE__</h1>
  <p class="sub">__SUBTITLE__ · __TOTAL__ samples total · icicle (root on top) — click a frame to zoom, gray frames to zoom out</p>
  <div class="bar">
    <button id="reset">Reset</button>
    <input id="search" type="search" placeholder="highlight (substring)…">
    <span id="crumb"></span>
  </div>
  <svg id="fg" xmlns="http://www.w3.org/2000/svg"></svg>
</div><div class="tt" id="tt"></div>
<script>
const TREE=__TREE_JSON__, TOTAL=TREE.v, ROW=17, W=1200;
const svg=document.getElementById('fg'), tip=document.getElementById('tt');
function ann(n,p){n.parent=p;(n.c||[]).forEach(c=>ann(c,n));} ann(TREE,null);
let focus=TREE, query="", RECTS=[];
function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function color(name,m){ if(m) return '#c026d3';
  let h=0; for(let i=0;i<name.length;i++) h=(h*31+name.charCodeAt(i))>>>0;
  return `rgb(${205+h%50},${Math.floor((h/53)%230)},${Math.floor((h/1913)%55)})`; }
function anc(n){const a=[];for(let p=n;p;p=p.parent)a.unshift(p);return a;}
function layout(){
  RECTS=[]; const a=anc(focus), ctx=a.slice(0,a.length-1);
  ctx.forEach((n,i)=>RECTS.push({node:n,x:0,w:W,y:i*ROW,ctx:true}));
  const base=ctx.length;
  (function rec(n,x,w,d){ RECTS.push({node:n,x,w,y:(base+d)*ROW});
    let cx=x; for(const c of (n.c||[])){ const cw=w*c.v/n.v; if(cw>=0.4) rec(c,cx,cw,d+1); cx+=cw; } })(focus,0,W,0);
  draw(); crumb();
}
function crumb(){ document.getElementById('crumb').textContent = anc(focus).map(n=>n.n).join('  ›  '); }
function draw(){
  const q=query.toLowerCase(); let maxY=0, p=[];
  for(let i=0;i<RECTS.length;i++){ const r=RECTS[i]; if(r.y>maxY)maxY=r.y;
    const m=q&&r.node.n.toLowerCase().includes(q);
    const fill=r.ctx?'#9a9a9a':color(r.node.n,m);
    p.push(`<g data-i="${i}"><rect x="${r.x.toFixed(2)}" y="${r.y}" width="${Math.max(0,r.w-1).toFixed(2)}" height="${ROW-1}" rx="2" fill="${fill}"${r.ctx?' opacity="0.5"':''}/>`);
    if(r.w>26){ const mc=Math.floor(r.w/6.4); let t=r.node.n; if(t.length>mc)t=t.slice(0,Math.max(1,mc-1))+'…';
      p.push(`<text x="${(r.x+3).toFixed(2)}" y="${r.y+ROW-5}" font-size="11" fill="#111">${esc(t)}</text>`); }
    p.push('</g>'); }
  svg.setAttribute('viewBox',`0 0 ${W} ${maxY+ROW+1}`); svg.style.height=(maxY+ROW+1)+'px';
  svg.innerHTML=p.join('');
}
svg.addEventListener('click',e=>{const g=e.target.closest('g[data-i]');if(!g)return;focus=RECTS[+g.dataset.i].node;layout();});
svg.addEventListener('mousemove',e=>{const g=e.target.closest('g[data-i]');if(!g){tip.style.opacity=0;return;}
  const n=RECTS[+g.dataset.i].node;
  tip.innerHTML=`<b>${esc(n.n)}</b><br>${n.v} samples · ${(100*n.v/TOTAL).toFixed(2)}% total · ${(100*n.v/focus.v).toFixed(2)}% view`;
  tip.style.opacity=1; tip.style.left=Math.min(e.clientX+12,innerWidth-tip.offsetWidth-8)+'px'; tip.style.top=(e.clientY+12)+'px';});
svg.addEventListener('mouseleave',()=>tip.style.opacity=0);
document.getElementById('reset').onclick=()=>{focus=TREE;layout();};
document.getElementById('search').oninput=e=>{query=e.target.value.trim();draw();};
layout();
</script></body></html>
'''

INDEX_TEMPLATE = r'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>SDITH profiling</title>
<style>
  body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f9f9f7;color:#0b0b0b;}
  @media (prefers-color-scheme: dark){body{background:#0d0d0d;color:#fff;}}
  .wrap{max-width:900px;margin:0 auto;padding:22px;}
  h1{font-size:18px;margin:0 0 4px;} .sub{font-size:12.5px;color:#777;margin:0 0 16px;}
  table{border-collapse:collapse;width:100%;font-size:13px;}
  td{padding:7px 8px;border-bottom:1px solid rgba(128,128,128,.25);vertical-align:top;}
  a{color:#2a78d6;} pre{font-size:11px;overflow:auto;background:rgba(128,128,128,.08);padding:8px;border-radius:6px;}
  details summary{cursor:pointer;color:#777;font-size:12px;}
  code{background:rgba(128,128,128,.15);padding:1px 5px;border-radius:4px;}
</style></head><body><div class="wrap">
<h1>SDITH profiling — current repo</h1>
<p class="sub">Generated __GENDATE__. Flame graphs from <code>perf</code> (task-clock, dwarf stacks);
callgrind from <code>valgrind --tool=callgrind --cache-sim=yes --branch-sim=yes</code>.
Open a <code>callgrind.out.*</code> with <code>kcachegrind</code> or
<code>callgrind_annotate callgrind.out.CATx</code>.</p>
<table><tbody>
__ROWS__
</tbody></table>
</div></body></html>
'''

if __name__ == "__main__":
    main()
