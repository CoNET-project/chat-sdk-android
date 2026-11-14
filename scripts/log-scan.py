#!/usr/bin/env python3
"""Log scan for spec 25.26.5 (T-157). Standard library only; Python 3.9 or later.

Reads the pattern file (log-scan-patterns.v1.json) and the BIP-39 English word list, scans each --source file line
by line, and prints a JSON report. The report never repeats matched text: it names the pattern id, the source id,
the line number and the column offset, and gives counts and file hashes.

Exit codes:
  0  no failing hit
  1  at least one failing hit (any pattern except LS-M4 and LS-F1-without-fixtures)
  2  no failing hit, but LS-M4 needs manual review (a run of 12 or more BIP-39 words)
  3  canary not detected: the run is invalid (spec 25.26.5, "金丝雀自检")

Usage:
  scripts/log-scan.py --patterns spec/log-scan-patterns.v1.json --wordlist spec/bip39-english.txt \
      [--fixtures F.json] [--allow F.txt] [--report OUT.json] --source SRC-3=PATH [--source SRC-9=PATH ...]

--fixtures: JSON object mapping each LS-F1 name (for example "DEK") to its hex value. Without it, LS-F1 is not
loaded and the report lists it under not_loaded. --allow: lines of 64-hex values allowed for LS-G1 (default none).
"""
import argparse
import datetime
import hashlib
import json
import re
import sys

CANARY_PREFIX = "log-scan canary: "
MANUAL_RUN = 12


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compile_patterns(spec, fixtures):
    """Returns (regex list, wordlist-run list, not_loaded list). Each regex entry: (id, compiled, failOn)."""
    regexes = []
    runs = []
    not_loaded = []
    for p in spec["patterns"]:
        pid = p["id"]
        kind = p["kind"]
        fail_on = p.get("failOn", "hit")
        if kind == "literal":
            flags = re.IGNORECASE if p.get("caseInsensitive") else 0
            regexes.append((pid, re.compile(re.escape(p["value"]), flags), fail_on))
        elif kind == "regex":
            flags = re.IGNORECASE if p.get("caseInsensitive") else 0
            regexes.append((pid, re.compile(p["value"], flags), fail_on))
        elif kind == "wordlist-run":
            runs.append((pid, int(p.get("minRun", MANUAL_RUN)), fail_on))
        elif kind == "fixture":
            if not fixtures:
                not_loaded.append(pid)
                continue
            for name in p.get("names", []):
                value = fixtures.get(name)
                if not value:
                    not_loaded.append("%s:%s" % (pid, name))
                    continue
                raw = value.lower().removeprefix("0x")
                variants = [re.escape(raw), re.escape("0x" + raw)]
                try:
                    import base64
                    b64 = base64.b64encode(bytes.fromhex(raw)).decode("ascii")
                    variants.append(re.escape(b64))
                except ValueError:
                    pass
                regexes.append((pid, re.compile("|".join(variants), re.IGNORECASE), fail_on))
        else:
            not_loaded.append("%s:unknown-kind" % pid)
    return regexes, runs, not_loaded


def canonical_regexes(neg):
    """25.52CG.3, CJ.1, CK.7, CL.1: the canonical pattern ids of the vector's logScan.patterns. The value of each is the SHA-256 of
    "hex:" + id (its sha256Label). The control pattern is the exception: its value is the SHA-256 of its inputString, which the vector
    gives. Each id is reported under its own name. LS-G1 is a separate check and is reported separately."""
    logscan = neg.get("logScan") or {}
    control = logscan.get("controlPattern") or {}
    out = []
    for p in logscan.get("patterns", []):
        is_control = p.get("id") == control.get("id")
        if is_control and control.get("inputString"):
            text = control["inputString"]
        else:
            text = "hex:" + (p.get("sha256Label") or p["id"])
        value = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if is_control and control.get("value") and value != control["value"]:
            sys.exit("controlPattern value does not match its inputString: %s" % p["id"])
        out.append((p["id"], re.compile(re.escape(value), re.IGNORECASE), "hit"))
    return out


def scan_text(text, regexes, runs, wordset, allow):
    """Yields (pattern_id, line_no, column, fail_on, extra) for each hit. Never yields matched text."""
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pid, rx, fail_on in regexes:
            for m in rx.finditer(line):
                value = m.group(0).lower().removeprefix("0x")
                if pid == "LS-G1" and value in allow:
                    continue
                yield pid, line_no, m.start() + 1, fail_on, None
        if runs:
            longest = 0
            current = 0
            for tok in re.findall(r"[a-z]+", line.lower()):
                if tok in wordset:
                    current += 1
                    longest = max(longest, current)
                else:
                    current = 0
            for pid, min_run, fail_on in runs:
                if longest >= min_run:
                    yield pid, line_no, 0, fail_on, longest


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patterns", required=True)
    ap.add_argument("--wordlist", required=True)
    ap.add_argument("--fixtures")
    ap.add_argument("--allow")
    ap.add_argument("--report")
    ap.add_argument("--source", action="append", default=[], metavar="ID=PATH")
    ap.add_argument("--canonical", help="negative-tests-v1.json: the canonical ids of logScan.patterns (25.52CG.3)")
    args = ap.parse_args()

    spec = load_json(args.patterns)
    fixtures = load_json(args.fixtures) if args.fixtures else None
    with open(args.wordlist, "r", encoding="utf-8") as f:
        wordset = set(w for w in f.read().split("\n") if w)
    allow = set()
    # digestAllowlist (25.26.5 LS-G1, r3g): exact full SHA-256 literals, each listed by name in the pattern file. A 64-hex
    # value is allowed only when the whole value equals one of them. Nothing else is relaxed.
    listed = (spec.get("digestAllowlist") or {}).get("entries", [])
    listed_count = 0
    for entry in listed:
        if isinstance(entry, dict) and entry.get("sha256"):
            allow.add(entry["sha256"].lower())
            listed_count += 1
    if args.allow:
        with open(args.allow, "r", encoding="utf-8") as f:
            for line in f:
                v = line.strip().lower().removeprefix("0x")
                if v:
                    allow.add(v)

    regexes, runs, not_loaded = compile_patterns(spec, fixtures)
    if args.canonical:
        regexes.extend(canonical_regexes(load_json(args.canonical)))

    # Canary self-test (spec 25.26.5): a line with LS-K1 must be detected, or the run is invalid.
    k1 = next(p["value"] for p in spec["patterns"] if p["id"] == "LS-K1")
    canary_hit = False
    for pid, _, _, _, _ in scan_text(CANARY_PREFIX + k1 + "\n", regexes, runs, wordset, allow):
        if pid == "LS-K1":
            canary_hit = True

    sources = []
    hits = {}
    locations = []
    manual = []
    failing = 0
    for item in args.source:
        if "=" not in item:
            sys.exit("bad --source %r (want ID=PATH)" % item)
        sid, path = item.split("=", 1)
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8", errors="replace")
        sources.append({
            "id": sid,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "lines": text.count("\n") + (0 if text.endswith("\n") or not text else 1),
        })
        for pid, line_no, col, fail_on, extra in scan_text(text, regexes, runs, wordset, allow):
            if fail_on == "manual-review-then-fail":
                manual.append({"pattern": pid, "source": sid, "line": line_no, "run": extra})
                continue
            hits[pid] = hits.get(pid, 0) + 1
            locations.append({"pattern": pid, "source": sid, "line": line_no, "column": col})
            failing += 1

    if not canary_hit:
        result = "invalid"
        code = 3
    elif failing:
        result = "fail"
        code = 1
    elif manual:
        result = "manual-review"
        code = 2
    else:
        result = "pass"
        code = 0

    report = {
        "scanner": "scripts/log-scan.py",
        "scanner_sha256": sha256_file(__file__),
        "patterns_file_sha256": sha256_file(args.patterns),
        "wordlist_sha256": sha256_file(args.wordlist),
        "generated_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "canary": {"required_pattern": "LS-K1", "detected": canary_hit},
        "sources": sources,
        "hit_counts": hits,
        "hit_locations": locations,
        "manual_review": manual,
        "not_loaded": not_loaded,
        "digest_allowlist_entries": listed_count,
        "allowlist_entries": len(allow),
        "result": result,
    }
    text = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(text)
        report_sha = sha256_text(text)
        sys.stderr.write("report sha256 %s\n" % report_sha)
    sys.stdout.write(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
