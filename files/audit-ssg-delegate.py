#!/usr/bin/env python3
"""Comment out audit rules this role emits that the SSG/SCAP base profile already provides.

WHY THIS EXISTS
---------------
`augenrules` performs NO deduplication. Its assembly stage strips comments, hoists
`-D`/`-b`/`-f`/`-e`, and emits every remaining rule verbatim (see the awk block in
/usr/sbin/augenrules). So when this role emits a rule the SSG base profile has already
written to another file in rules.d, the kernel rejects the second copy with
"Rule exists" and augenrules ABORTS THE ENTIRE LOAD at that line - dropping every rule
after it AND the trailing `-e 2`, leaving the audit configuration mutable.

Because `-D` is hoisted to line 1 the kernel is flushed before loading, so a collision is
always WITHIN the assembled file, never against pre-existing kernel state.

WHY RUNTIME AND NOT A STATIC EDIT
---------------------------------
Which rules the base profile provides varies by SSG version, profile, and OS major.
Hardcoding a removal list bakes in an assumption that goes stale: a previous attempt
deleted four rules based on a one-shot measurement that turned out to have missed four
more, because the comparison did not normalise `-F` field ordering.

Deciding at apply time is self-correcting, and it preserves the role's contract in both
directions: on an SSG-remediated host the duplicate is delegated, and on a host WITHOUT
the base profile nothing matches, nothing is commented, and the role still fills the gap
as documented.

NORMALISATION
-------------
Three encodings mean the same thing to the kernel and must compare equal:
  -S a,b,c            ==  -S a -S b -S c        (and order within either form)
  -k KEY              ==  -F key=KEY
  -F x -F y           ==  -F y -F x             (field order is not significant)

Matching is EXACT after normalisation - never fuzzy. A false positive here silently
drops real audit coverage, which is worse than the loud failure it replaces, so the
script errs toward leaving a rule in place and reports every decision it makes.

Exit codes: 0 ok (see JSON on stdout), 2 usage/IO error.
"""

import argparse
import json
import os
import re
import sys

MARKER = "#DELEGATED-TO-BASE-PROFILE"


def normalise(line):
    """Return a canonical form of an audit rule, or None if not a rule."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    # Only -a/-w rules participate; -D/-b/-f/-e are control lines augenrules hoists.
    if not (s.startswith("-a") or s.startswith("-w")):
        return None

    s = re.sub(r"-F\s+key=(\S+)", r"-k \1", s)

    syscalls = []

    def _collect(m):
        syscalls.extend(x for x in m.group(1).split(",") if x)
        return " "

    s = re.sub(r"-S\s+([A-Za-z0-9_,]+)", _collect, s)
    s = re.sub(r"\s+", " ", s).strip()

    # Sort -F fields so ordering is not significant.
    if " -F " in s:
        head, _, rest = s.partition(" -F ")
        fields = sorted(f.strip() for f in rest.split(" -F "))
        s = head + " -F " + " -F ".join(fields)

    if syscalls:
        s += " -S " + ",".join(sorted(set(syscalls)))
    return s


def load_base(rules_dir, owned):
    """Map normalised rule -> 'file:line' for every rules.d file this role does not own."""
    base = {}
    # A host with no rules.d at all (a build container, or a system where the base profile
    # was never applied) is a legitimate case, not an error: nothing to delegate to, so
    # every rule stays. Failing here would break the role on exactly the hosts where its
    # gap-filling matters most.
    if not os.path.isdir(rules_dir):
        return base
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith(".rules") or name in owned:
            continue
        path = os.path.join(rules_dir, name)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    n = normalise(line)
                    if n is not None:
                        base.setdefault(n, "%s:%d" % (name, i))
        except OSError as exc:
            print("cannot read %s: %s" % (path, exc), file=sys.stderr)
            raise
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="final rules file this role owns")
    ap.add_argument("--from", dest="source", default=None,
                    help="candidate file to read instead of --target (render-then-delegate; "
                         "keeps the flow convergent because the template can rewrite the "
                         "candidate every run without churning the live file)")
    ap.add_argument("--rules-dir", default="/etc/audit/rules.d")
    ap.add_argument("--owned", default="", help="comma-separated basenames this role owns")
    ap.add_argument("--check", action="store_true", help="report only, write nothing")
    args = ap.parse_args()

    owned = {x for x in args.owned.split(",") if x}
    owned.add(os.path.basename(args.target))

    source = args.source or args.target
    if not os.path.exists(source):
        print(json.dumps({"changed": False, "reason": "source missing", "delegated": []}))
        return 0

    base = load_base(args.rules_dir, owned)

    with open(source, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    existing = []
    if os.path.exists(args.target):
        with open(args.target, encoding="utf-8") as fh:
            existing = fh.read().splitlines()

    out, delegated, restored = [], [], []
    for line in lines:
        # Idempotency: a previously delegated rule is re-evaluated from its saved original,
        # so a rule the base profile STOPS providing is automatically restored rather than
        # staying suppressed forever.
        if line.startswith(MARKER):
            original = line.split("|", 1)[1] if "|" in line else ""
            n = normalise(original)
            if n is not None and n in base:
                out.append("%s %s|%s" % (MARKER, base[n], original))
                delegated.append({"rule": original.strip(), "provided_by": base[n]})
            else:
                out.append(original)
                restored.append(original.strip())
            continue

        n = normalise(line)
        if n is not None and n in base:
            out.append("%s %s|%s" % (MARKER, base[n], line))
            delegated.append({"rule": line.strip(), "provided_by": base[n]})
        else:
            out.append(line)

    # Compare against what is ALREADY on the target, not against the candidate. The
    # template rewrites the candidate every run, so comparing to it would report changed
    # forever - which notifies the reload handler forever, and on a node that has since
    # reached `-e 2` that is a permanent failure. Converges on run 2.
    changed = out != existing
    if changed and not args.check:
        tmp = args.target + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
        mode = os.stat(args.target).st_mode & 0o7777 if os.path.exists(args.target) else 0o640
        os.chmod(tmp, mode)
        os.replace(tmp, args.target)

    print(json.dumps({
        "changed": changed,
        "delegated_count": len(delegated),
        "restored_count": len(restored),
        "base_rules_seen": len(base),
        "delegated": delegated,
        "restored": restored,
    }, indent=None))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - surface any failure as a non-zero exit
        print("audit-ssg-delegate failed: %s" % exc, file=sys.stderr)
        sys.exit(2)
