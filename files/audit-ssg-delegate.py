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
    """Return a canonical form of an audit rule, or None if the line is not a rule.

    Parses the rule into TOKENS rather than rewriting the string. An earlier version did
    string surgery - converting `-F key=X` in place, stripping `-S`, then sorting by
    splitting on " -F " - which left non-field tokens such as `-k` glued to whichever
    field happened to precede them. Two equivalent rules then canonicalised differently
    and the duplicate survived, which is the exact abort this helper exists to prevent:

        base: -a always,exit -F auid!=unset -S fchownat -S chown -F arch=b64 \
              -F key=perm_mod -S fchown -S lchown -F auid>=1000
        role: -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown \
              -F auid>=1000 -F auid!=unset -k perm_mod

    Those are the same rule to the kernel. Tokenising makes them compare equal regardless
    of how the flags are interleaved.

    An unrecognised token is kept as an opaque field rather than dropped, so an
    unfamiliar construct makes a rule LESS likely to match, never more. Failing to
    delegate is a loud, recoverable duplicate error; delegating wrongly silently removes
    audit coverage.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    toks = s.split()
    # Only -a/-A syscall rules and -w watches participate. -D/-b/-f/-e are control lines
    # that augenrules hoists out of the rule body entirely.
    if not toks or toks[0] not in ("-a", "-A", "-w"):
        return None

    action = watch = perms = None
    syscalls, fields, keys = set(), set(), set()

    i = 0
    while i < len(toks):
        tok = toks[i]
        val = toks[i + 1] if i + 1 < len(toks) else None
        if tok in ("-a", "-A") and val is not None:
            # -A prepends and -a appends; the resulting RULE is identical, and the kernel
            # rejects the duplicate either way, so insertion order is not part of identity.
            action = val
            i += 2
        elif tok == "-w" and val is not None:
            watch = val
            i += 2
        elif tok == "-p" and val is not None:
            perms = "".join(sorted(set(val)))
            i += 2
        elif tok == "-S" and val is not None:
            syscalls.update(x for x in val.split(",") if x)
            i += 2
        elif tok in ("-F", "-C") and val is not None:
            if val.startswith("key="):
                keys.add(val[4:])
            else:
                fields.add(val)
            i += 2
        elif tok == "-k" and val is not None:
            keys.add(val)
            i += 2
        else:
            fields.add(tok)
            i += 1

    parts = []
    if watch:
        parts.append("w:" + watch)
    if action:
        parts.append("a:" + action)
    if perms:
        parts.append("p:" + perms)
    if syscalls:
        parts.append("S:" + ",".join(sorted(syscalls)))
    if fields:
        parts.append("F:" + ",".join(sorted(fields)))
    if keys:
        parts.append("k:" + ",".join(sorted(keys)))
    return " ".join(parts)


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
