#!/usr/bin/env python3
"""Per-function test-coverage auditor for the vole-sd library.

Goal
----
*Prove* that every exported symbol that originates from ``src/*.c`` is
referenced by at least one test source in ``test/`` (``*.cpp`` / ``*.cc``).
Any exported ``src``-origin symbol that no test names is reported as
UNCOVERED and the script exits non-zero -- so this can be wired into ctest
as a gate that fails when the uncovered set grows (see TESTING_TODO.md).

Method
------
1. ``nm`` lists the exported (global) *defined* symbols in the built library.
   For a static archive, ``nm`` groups symbols under their object file
   (``gf256.c.o:`` ...); an object is treated as "src-origin" iff a matching
   ``src/<name>.c`` exists. That automatically excludes vendored ``lib/*``
   objects (keccak/aes/rijndael) and AVX2 objects not compiled on this arch.
   For a single-module shared library (``.so`` / ``.dylib``) there is no
   object grouping, so a best-effort fallback marks a symbol src-origin when
   its name appears as a definition-like token in ``src/*.c`` but not in any
   vendored ``lib`` source (documented as best-effort; the archive is exact).
2. Each test source is scanned with a small comment/string-aware state
   machine (line comments, block comments and double-quoted string bodies are
   dropped) and tokenised into C identifiers. A symbol counts as *referenced*
   iff its C name is one of those code tokens -- exact, word-boundary matching
   by construction, and immune to a symbol being "documented but not tested".
3. Symbols in ALLOWLIST are treated as deliberately-internal and skipped.

Portability / requirements
---------------------------
* POSIX + Python 3 (>= 3.9; validated against the 3.14 stdlib surface).
* No third-party dependencies. The only external tool is ``nm`` (override via
  ``--nm`` or the ``NM`` environment variable).
* Symbol name mangling (the Mach-O leading underscore) is auto-detected and
  normalised, so the same script works on Linux (ELF) and macOS (Mach-O).

Exit status
-----------
* ``0`` -- every src-origin exported symbol is referenced (or allowlisted).
* ``1`` -- one or more src-origin exported symbols are UNCOVERED.
* ``2`` -- usage / environment error (library or ``nm`` missing, nothing parsed).

Known limitations
-----------------
* A symbol reached only via ``##`` token-pasting in a test macro will show as
  uncovered (its full name never appears as a literal token). Prefer a direct
  reference in the test, or add a justified ALLOWLIST entry.
* The shared-library fallback (#1) is heuristic; run against the static
  archive (the default) for an exact result.
"""

import argparse
import os
import re
import subprocess
import sys


def die(msg):
    """Report an environment/usage error and exit 2 (distinct from a coverage
    failure, which exits 1)."""
    sys.stderr.write(msg.rstrip("\n") + "\n")
    raise SystemExit(2)

# --------------------------------------------------------------------------
# ALLOWLIST -- deliberately-internal / wrapper symbols that are exported for
# linkage but are NOT expected to have a direct test of their own.
#
# Keep this SMALL. Every entry must carry a one-line justification, and each
# should be the *only* untested member of a family whose active path is
# already covered. Stale entries (referenced now, or no longer exported) are
# reported as warnings so the list stays honest.
#
# Names are the plain C identifiers (no Mach-O leading underscore).
ALLOWLIST = {
    # Portable software fallback for binval_of(): used only where the
    # __builtin_ctz path in binval_of() is unavailable. The active builtin
    # path (binval_of) is the one exercised on supported toolchains.
    "binval_of_compat",
}


# --------------------------------------------------------------------------
# nm parsing
# --------------------------------------------------------------------------

# Archive member header, e.g. "gf256.c.o:" (BSD nm and GNU nm both emit this
# when nm is run on an archive without -A).
_HEADER_RE = re.compile(r"^(?P<obj>\S+\.(?:o|obj|lo)):$")

# A defined symbol line, e.g. "0000000000000010 T _gf256v_mul".
# The address is optional (absolute/common symbols may omit it).
_SYM_RE = re.compile(r"^\s*[0-9a-fA-F]*\s*(?P<type>[A-Za-z])\s+(?P<name>\S+)\s*$")

# -A / --print-file-name style line, e.g.
# "build/libvole.a:gf256.c.o: 0000000000000010 T _gf256v_mul".
_AFORM_RE = re.compile(
    r"^(?P<loc>\S+\.(?:o|obj|lo)):\s*[0-9a-fA-F]*\s*(?P<type>[A-Za-z])\s+(?P<name>\S+)\s*$"
)


def _member_basename(field):
    """Reduce an nm location field to a bare object basename.

    Handles both "build/libvole.a:gf256.c.o" (path + archive + member joined
    by '/' and ':') and a plain "gf256.c.o".
    """
    return field.rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def run_nm(nm, library):
    """Return nm output listing exported (-g) defined (--defined-only) symbols."""
    cmd = [nm, "-g", "--defined-only", library]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        die("error: nm not found (looked for %r); set --nm or $NM" % nm)
    if proc.returncode != 0:
        # Some very old BSD nm builds lack --defined-only; retry without it and
        # filter undefined (U) lines ourselves.
        proc = subprocess.run(
            [nm, "-g", library], capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            die("error: nm failed on %s" % library)
    return proc.stdout


def parse_nm(text):
    """Parse nm output into {object_basename: set(raw_symbol_name)}.

    Supports the archive member-header format (primary) and the -A prefixed
    format (fallback). Undefined ('U') symbols are ignored.
    """
    groups = {}
    current = None

    # Primary: member-header grouped format.
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        header = _HEADER_RE.match(stripped)
        if header:
            current = _member_basename(header.group("obj"))
            groups.setdefault(current, set())
            continue
        sym = _SYM_RE.match(line)
        if sym and current is not None:
            if sym.group("type") == "U":  # defensive; -g w/o --defined-only
                continue
            groups[current].add(sym.group("name"))

    if groups:
        return groups

    # Fallback: -A prefixed format (no member headers were seen).
    for line in text.splitlines():
        am = _AFORM_RE.match(line.strip())
        if not am or am.group("type") == "U":
            continue
        obj = _member_basename(am.group("loc"))
        groups.setdefault(obj, set()).add(am.group("name"))
    return groups


# --------------------------------------------------------------------------
# src-origin determination
# --------------------------------------------------------------------------

def src_c_basenames(src_dir):
    """Set of C source basenames in src/, e.g. {'gf256.c', 'commons.c', ...}."""
    if not os.path.isdir(src_dir):
        die("error: src dir not found: %s" % src_dir)
    return {
        name
        for name in os.listdir(src_dir)
        if name.endswith(".c") and os.path.isfile(os.path.join(src_dir, name))
    }


def object_source(obj, src_basenames):
    """Return the src/*.c basename an object came from, or None.

    'gf256.c.o' -> 'gf256.c'; 'gf256.o' -> 'gf256.c' (only if src/gf256.c exists).
    """
    base = obj[:-2] if obj.endswith(".o") else obj
    for cand in (base, base + ".c"):
        if cand in src_basenames:
            return cand
    return None


# --------------------------------------------------------------------------
# symbol-name normalisation (Mach-O leading underscore)
# --------------------------------------------------------------------------

def detect_underscore_prefix(names):
    """True if these symbols use the Mach-O leading-underscore convention."""
    if not names:
        return False
    lead = sum(1 for n in names if n.startswith("_"))
    return lead >= 0.8 * len(names)


def c_name(raw, strip_underscore):
    """Map a raw nm symbol to the C identifier used in source."""
    if strip_underscore and raw.startswith("_"):
        return raw[1:]
    return raw


# --------------------------------------------------------------------------
# test-source scanning
# --------------------------------------------------------------------------

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def strip_comments_and_strings(text):
    """Remove // and /* */ comments and double-quoted string bodies.

    Single quotes are intentionally *not* treated as string delimiters, so C++
    digit separators (1'000'000) and char literals are left alone. Dropping
    string bodies is conservative: real references to exported symbols are code
    identifiers, never string contents, so this can only ever under-count
    (fail louder), never claim coverage that is not there.
    """
    out = []
    i = 0
    n = len(text)
    state = "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"
                i += 2
            elif c == "/" and nxt == "*":
                state = "block"
                i += 2
            elif c == '"':
                state = "dq"
                out.append(" ")
                i += 1
            else:
                out.append(c)
                i += 1
        elif state == "line":
            if c == "\n":
                state = "code"
                out.append(c)
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                out.append(" ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        else:  # dq (double-quoted string)
            if c == "\\":
                i += 2  # skip the escaped char (handles \")
            elif c == '"':
                state = "code"
                out.append(" ")
                i += 1
            else:
                i += 1
    return "".join(out)


def collect_referenced_tokens(test_dir):
    """Union of C identifiers appearing in code (not comments/strings) of tests."""
    if not os.path.isdir(test_dir):
        die("error: test dir not found: %s" % test_dir)
    tokens = set()
    files = sorted(
        os.path.join(test_dir, name)
        for name in os.listdir(test_dir)
        if name.endswith(".cpp") or name.endswith(".cc")
    )
    if not files:
        die("error: no test/*.cpp or test/*.cc files found in %s" % test_dir)
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            code = strip_comments_and_strings(fh.read())
        tokens.update(_IDENT_RE.findall(code))
    return tokens, files


def tokens_in_src(src_dir, src_basenames):
    """Identifiers appearing in src/*.c (used only for the shared-lib fallback)."""
    tokens = set()
    for name in src_basenames:
        path = os.path.join(src_dir, name)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            tokens.update(_IDENT_RE.findall(strip_comments_and_strings(fh.read())))
    return tokens


def tokens_in_lib(repo_root):
    """Identifiers appearing in vendored lib/ sources (shared-lib fallback)."""
    lib_dir = os.path.join(repo_root, "lib")
    tokens = set()
    if not os.path.isdir(lib_dir):
        return tokens
    for root, _dirs, names in os.walk(lib_dir):
        for name in names:
            if name.endswith((".c", ".h", ".cpp", ".cc", ".inc")):
                path = os.path.join(root, name)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        tokens.update(
                            _IDENT_RE.findall(strip_comments_and_strings(fh.read()))
                        )
                except OSError:
                    pass
    return tokens


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def resolve_library(arg, repo_root):
    if arg:
        if not os.path.exists(arg):
            die("error: library not found: %s" % arg)
        return arg
    for cand in ("libvole.a", "libvole.so", "libvole.dylib"):
        path = os.path.join(repo_root, "build", cand)
        if os.path.exists(path):
            return path
    die(
        "error: no library given and none of build/libvole.{a,so,dylib} exist; "
        "build the project or pass the path explicitly"
    )


def build_parser():
    p = argparse.ArgumentParser(
        description="Prove per-function test coverage of the vole-sd library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "library",
        nargs="?",
        default=None,
        help="path to the built library (default: build/libvole.a, then .so/.dylib)",
    )
    p.add_argument("--src-dir", default=None, help="path to src/ (default: <repo>/src)")
    p.add_argument(
        "--test-dir", default=None, help="path to test/ (default: <repo>/test)"
    )
    p.add_argument(
        "--nm",
        default=os.environ.get("NM", "nm"),
        help="nm binary to use (default: $NM or 'nm')",
    )
    p.add_argument(
        "--list-covered",
        action="store_true",
        help="also print the covered symbols (grouped by source file)",
    )
    return p


def main(argv):
    args = build_parser().parse_args(argv)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    src_dir = args.src_dir or os.path.join(repo_root, "src")
    test_dir = args.test_dir or os.path.join(repo_root, "test")
    library = resolve_library(args.library, repo_root)

    src_basenames = src_c_basenames(src_dir)
    groups = parse_nm(run_nm(args.nm, library))
    if not groups:
        die("error: nm produced no parseable symbols for %s" % library)

    # Collect (raw_symbol, source_file) for every src-origin exported symbol.
    # If nm gave us object grouping (static archive) use it directly; otherwise
    # fall back to the shared-library heuristic.
    src_symbols = {}  # raw_symbol -> source basename
    has_object_grouping = any(
        object_source(obj, src_basenames) for obj in groups
    )
    if has_object_grouping:
        for obj, syms in groups.items():
            source = object_source(obj, src_basenames)
            if source is None:
                continue  # vendored lib / non-src object
            for sym in syms:
                src_symbols[sym] = source
    else:
        # Single-module shared library: no object grouping available.
        all_syms = set().union(*groups.values()) if groups else set()
        strip = detect_underscore_prefix(all_syms)
        src_tokens = tokens_in_src(src_dir, src_basenames)
        lib_tokens = tokens_in_lib(repo_root)
        for sym in all_syms:
            name = c_name(sym, strip)
            if name in src_tokens and name not in lib_tokens:
                src_symbols[sym] = "src/*.c (shared-lib heuristic)"
        sys.stderr.write(
            "warning: %s has no object grouping; using best-effort shared-lib "
            "heuristic. Run against the static archive for an exact result.\n"
            % os.path.basename(library)
        )

    if not src_symbols:
        die(
            "error: no src-origin exported symbols found; is %s the vole-sd "
            "library and does src/ contain the sources?" % library
        )

    strip = detect_underscore_prefix(set(src_symbols))
    referenced, test_files = collect_referenced_tokens(test_dir)

    covered = {}     # source -> sorted list of covered names
    uncovered = {}   # source -> sorted list of uncovered names
    allowlisted_hit = []  # (name, source) skipped via ALLOWLIST
    for raw, source in sorted(src_symbols.items(), key=lambda kv: (kv[1], kv[0])):
        name = c_name(raw, strip)
        if name in ALLOWLIST:
            allowlisted_hit.append((name, source))
            continue
        bucket = covered if name in referenced else uncovered
        bucket.setdefault(source, []).append(name)

    # Allowlist hygiene: entries that no longer apply.
    all_names = {c_name(r, strip) for r in src_symbols}
    referenced_allow = sorted(
        n for (n, _s) in allowlisted_hit if n in referenced
    )
    stale_allow = sorted(ALLOWLIST - all_names)

    total = len(src_symbols)
    n_allow = len(allowlisted_hit)
    n_uncovered = sum(len(v) for v in uncovered.values())
    n_covered = total - n_allow - n_uncovered

    # ---- report ----
    out = sys.stdout.write
    out("vole-sd per-function coverage audit\n")
    out("  library : %s\n" % library)
    out("  src dir : %s\n" % src_dir)
    out("  tests   : %d file(s) in %s\n" % (len(test_files), test_dir))
    out("  symbols : %d exported src-origin  (%d covered, %d allowlisted, %d UNCOVERED)\n"
        % (total, n_covered, n_allow, n_uncovered))
    out("\n")

    if args.list_covered and covered:
        out("COVERED exported symbols (referenced by a test):\n")
        for source in sorted(covered):
            out("  %s:\n" % source)
            for name in sorted(covered[source]):
                out("    %s\n" % name)
        out("\n")

    if allowlisted_hit:
        out("ALLOWLISTED (deliberately internal, not required to be tested):\n")
        for name, source in sorted(allowlisted_hit):
            out("  %-40s [%s]\n" % (name, source))
        out("\n")

    for note, items in (
        ("warning: ALLOWLIST entries now referenced by a test (drop them)", referenced_allow),
        ("warning: ALLOWLIST entries no longer exported (stale)", stale_allow),
    ):
        if items:
            out("%s:\n" % note)
            for name in items:
                out("  %s\n" % name)
            out("\n")

    if uncovered:
        out("UNCOVERED exported symbols (no test references them):\n")
        for source in sorted(uncovered):
            out("  %s:\n" % source)
            for name in sorted(uncovered[source]):
                out("    %s\n" % name)
        out("\n")
        out("RESULT: FAIL -- %d uncovered src-origin exported symbol(s).\n" % n_uncovered)
        return 1

    out("RESULT: PASS -- every src-origin exported symbol is referenced by a test.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
