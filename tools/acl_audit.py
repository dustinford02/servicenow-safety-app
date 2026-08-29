#!/usr/bin/env python3
"""
ACL audit for ServiceNow update-set XML exports.

Replaces the aclLinter.js shipped in governed-checks-app, which reported a
PASSING check on this repository's real update set because it looked for
<sys_security_acl> as a direct child of <unload>. It is not there. A real
export nests every record inside:

    <unload>
      <sys_remote_update_set/>
      <sys_update_xml>
        <payload><![CDATA[
          <record_update table="sys_security_acl">
            <sys_security_acl> ... </sys_security_acl>
          </record_update>
        ]]></payload>
      </sys_update_xml>
      ... x36
    </unload>

This script does the two-stage parse that structure requires, and it
fails closed: a file that looks like an update set but yields no
parseable records is an ERROR, never a silent pass. That inversion is the
whole point of the rewrite.

Standard library only. No pip install, no package.json, no lockfile.

Exit codes:
    0  no failures (notices and warnings may still be printed)
    1  at least one failure
    2  could not parse, or parsed zero records from a file that should
       contain them
"""

import sys
import glob
import xml.etree.ElementTree as ET
from pathlib import Path

WRITE_OPS = {"write", "delete", "create"}


def text_of(elem, tag, default=""):
    """Child element text, or default. ServiceNow writes empty elements
    as <condition/>, which ElementTree gives a text of None."""
    child = elem.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def is_true(elem, tag):
    return text_of(elem, tag).lower() == "true"


def extract_records(path):
    """Return (acls, role_links_by_acl_sysid, parse_note).

    Handles both the payload-wrapped update-set form and the flat
    direct-export form, because right-click -> Export -> XML produces the
    flat one and both are plausible things to find in a repository.
    """
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        return None, None, f"XML parse error: {exc}"

    root = tree.getroot()
    acls = []
    role_counts = {}

    # Stage 1: flat form. Direct children of <unload>.
    for acl in root.findall("sys_security_acl"):
        acls.append(acl)
    for link in root.findall("sys_security_acl_role"):
        ref = text_of(link, "sys_security_acl")
        if ref:
            role_counts[ref] = role_counts.get(ref, 0) + 1

    # Stage 2: payload-wrapped form. This is what ServiceNow actually
    # exports, and what the previous implementation missed entirely.
    for update in root.findall("sys_update_xml"):
        payload = update.find("payload")
        if payload is None or not payload.text:
            continue
        inner_text = payload.text.strip()
        if not inner_text.startswith("<"):
            continue
        try:
            inner = ET.fromstring(inner_text)
        except ET.ParseError:
            # One unparseable payload should not abort the file, but it
            # must not be invisible either.
            print(f"::warning file={path}::A <payload> block could not be parsed and was skipped")
            continue
        # inner is <record_update>; the record is its child.
        for acl in inner.findall("sys_security_acl"):
            acls.append(acl)
        for link in inner.findall("sys_security_acl_role"):
            ref = text_of(link, "sys_security_acl")
            if ref:
                role_counts[ref] = role_counts.get(ref, 0) + 1

    return acls, role_counts, None


def evaluate(acl, role_count):
    """Heuristic checks on one ACL. Returns a list of (level, message).

    These are 'worth a human look' signals, not a reimplementation of
    ServiceNow's evaluation engine: no role hierarchy, no dot-walk
    inheritance, no script-condition evaluation. Stated here so the
    output is not read as more authoritative than it is.
    """
    findings = []

    name = text_of(acl, "name", "(unnamed)")
    operation = text_of(acl, "operation").lower()
    sys_id = text_of(acl, "sys_id", "(no sys_id)")
    label = f'"{name}" [{operation or "no operation"}] {sys_id}'

    active = is_true(acl, "active")
    advanced = is_true(acl, "advanced")
    admin_overrides = is_true(acl, "admin_overrides")
    has_condition = bool(text_of(acl, "condition"))
    has_script = bool(text_of(acl, "script"))
    has_description = bool(text_of(acl, "description"))

    if active and not advanced and role_count == 0 and not has_condition and not has_script:
        level = "error" if operation in WRITE_OPS else "warning"
        findings.append((
            level,
            f"{label} is active with no roles, no condition and no script. "
            f"In ServiceNow that grants access to any user who can reach the application. "
            f"Add a role, a condition or a script check, or document why it is intentionally open."
        ))

    if active and admin_overrides and operation in {"write", "delete"} and role_count == 0:
        findings.append((
            "error",
            f"{label} allows {operation} with admin_overrides enabled and no roles attached. "
            f"Confirm this is intentional or scope it to a role."
        ))

    if not has_description:
        findings.append((
            "notice",
            f"{label} has no description. A one-line rationale makes future audits and "
            f"credential reviews substantially faster."
        ))

    return findings


def main(argv):
    patterns = argv[1:] or ["update-set/*.xml", "*.xml"]

    paths = []
    for pattern in patterns:
        paths.extend(sorted(glob.glob(pattern, recursive=True)))
    paths = [p for p in dict.fromkeys(paths) if Path(p).is_file()]

    if not paths:
        print(f"::error::No update-set XML matched {patterns}. Nothing was audited, "
              f"which is treated as a failure rather than a pass.")
        return 2

    total_acls = 0
    failures = warnings = notices = 0
    hard_error = False

    for path in paths:
        acls, role_counts, note = extract_records(path)

        if note:
            print(f"::error file={path}::{note}")
            hard_error = True
            continue

        if not acls:
            # THE FIX. The old implementation returned success here.
            print(f"::error file={path}::Parsed 0 sys_security_acl records from this file. "
                  f"Either it contains no ACLs, or the export format changed and this "
                  f"audit can no longer read it. Failing closed rather than reporting a pass.")
            hard_error = True
            continue

        total_acls += len(acls)
        print(f"{path}: {len(acls)} ACL record(s), {sum(role_counts.values())} role link(s)")

        for acl in acls:
            sys_id = text_of(acl, "sys_id")
            for level, message in evaluate(acl, role_counts.get(sys_id, 0)):
                # Annotated at file level deliberately. The records live
                # inside CDATA payloads, so any line number this script
                # invented would point at the wrong place. The ACL is
                # identified by name, operation and sys_id instead.
                print(f"::{level} file={path}::{message}")
                if level == "error":
                    failures += 1
                elif level == "warning":
                    warnings += 1
                else:
                    notices += 1

    print(f"\nAudited {len(paths)} file(s), {total_acls} ACL record(s): "
          f"{failures} failure, {warnings} warning, {notices} notice.")

    if hard_error:
        return 2
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
