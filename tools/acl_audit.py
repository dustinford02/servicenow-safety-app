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
        <action>INSERT_OR_UPDATE | DELETE</action>
        <payload><![CDATA[
          <record_update table="sys_security_acl">
            <sys_security_acl action="..."> ... </sys_security_acl>
          </record_update>
        ]]></payload>
      </sys_update_xml>
      ...
    </unload>

This script does the two-stage parse that structure requires, and it
fails closed: a file that looks like an update set but yields no
parseable records is an ERROR, never a silent pass. That inversion is the
whole point of the rewrite.

Deletions are not grants. An update set records a removed role link as a
<sys_update_xml> whose <action> is DELETE, while the wrapper element's own
action attribute still reads INSERT_OR_UPDATE. Counting every
<sys_security_acl_role> as a grant would let a deleted link make an
otherwise unprotected ACL look role-scoped. A record is treated as deleted
if either the wrapper <action> or the record's action attribute says
DELETE, and if the same sys_id appears more than once, deletion wins.

On top of the per-ACL heuristics, the audit asserts a contract
(tools/acl_contract.json by default): the exact set of live ACLs, each
one's live roles and condition, and the roles that must be able to reach
the application menu and modules. Any difference is a failure.

Standard library only. No pip install, no package.json, no lockfile.

Exit codes:
    0  no failures (notices and warnings may still be printed)
    1  at least one failure
    2  could not parse, parsed zero records from a file that should
       contain them, or the contract could not be loaded
"""

import argparse
import glob
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

WRITE_OPS = {"write", "delete", "create"}
NAV_TABLES = ("sys_app_application", "sys_ui_application", "sys_app_module", "sys_ui_module")
DEFAULT_CONTRACT = Path(__file__).resolve().parent / "acl_contract.json"


def text_of(elem, tag, default=""):
    """Child element text, or default. ServiceNow writes empty elements
    as <condition/>, which ElementTree gives a text of None."""
    child = elem.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def is_true(elem, tag):
    return text_of(elem, tag).lower() == "true"


def is_delete(record, wrapper=None):
    if (record.get("action") or "").upper() == "DELETE":
        return True
    return wrapper is not None and text_of(wrapper, "action").upper() == "DELETE"


@dataclass
class UpdateSet:
    """Live and deleted records of interest from one XML file."""
    acls: list = field(default_factory=list)
    deleted_acls: list = field(default_factory=list)
    # ACL sys_id -> sorted list of live role names.
    acl_roles: dict = field(default_factory=dict)
    # (ACL sys_id, role name) for every link removed by a DELETE.
    deleted_links: list = field(default_factory=list)
    # Live links whose ACL is not in this file: (ACL sys_id, role name).
    orphan_links: list = field(default_factory=list)
    roles: dict = field(default_factory=dict)          # role sys_id -> name
    contains: list = field(default_factory=list)       # (role name, contained role name)
    navigation: list = field(default_factory=list)     # (table, label, [role names])
    # Wrapper <type> values ("Access Control", "Module", ...), one per <sys_update_xml>.
    types: Counter = field(default_factory=Counter)

    @property
    def live_link_count(self):
        return sum(len(r) for r in self.acl_roles.values())


def iter_records(root, path):
    """Yield (record, wrapper) for every record in either export form.

    Flat form (right-click -> Export -> XML) puts records directly under
    <unload>; wrapper is None. Payload form, which is what ServiceNow's
    update set export produces, wraps each record in a CDATA payload.
    """
    for child in root:
        if child.tag not in ("sys_update_xml", "sys_remote_update_set"):
            yield child, None

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
        for record in inner:
            yield record, update


def _ref(record, tag):
    """(sys_id, name) of a reference element, name from its attributes if present."""
    elem = record.find(tag)
    if elem is None:
        return "", ""
    return (elem.text or "").strip(), elem.get("name") or elem.get("display_value") or ""


def extract_records(path):
    """Return (UpdateSet, parse_note). UpdateSet is None when parse_note is set."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        return None, f"XML parse error: {exc}"

    root = tree.getroot()
    us = UpdateSet()
    for update in root.findall("sys_update_xml"):
        us.types[text_of(update, "type", "(no type)")] += 1

    # Keyed by sys_id so a record that appears twice is counted once, and a
    # DELETE anywhere for that sys_id wins over an INSERT_OR_UPDATE.
    acls = {}
    links = {}
    containment = {}
    anonymous = 0

    for record, wrapper in iter_records(root, path):
        deleted = is_delete(record, wrapper)
        sys_id = text_of(record, "sys_id")
        if not sys_id:
            anonymous += 1
            sys_id = f"(no sys_id #{anonymous})"

        if record.tag == "sys_security_acl":
            prev = acls.get(sys_id)
            acls[sys_id] = (record, deleted or (prev is not None and prev[1]))
        elif record.tag == "sys_security_acl_role":
            prev = links.get(sys_id)
            acl_id, _ = _ref(record, "sys_security_acl")
            role = _ref(record, "sys_user_role")
            links[sys_id] = (acl_id, role, deleted or (prev is not None and prev[2]))
        elif record.tag == "sys_user_role" and not deleted:
            us.roles[sys_id] = text_of(record, "name")
        elif record.tag == "sys_user_role_contains":
            prev = containment.get(sys_id)
            containment[sys_id] = (_ref(record, "role"), _ref(record, "contains"),
                                   deleted or (prev is not None and prev[2]))
        elif record.tag in NAV_TABLES and not deleted:
            roles = [r.strip() for r in text_of(record, "roles").split(",") if r.strip()]
            label = text_of(record, "title") or text_of(record, "name") or sys_id
            us.navigation.append((record.tag, label, roles))

    def role_name(ref):
        sys_id, name = ref
        return name or us.roles.get(sys_id) or sys_id or "(no role)"

    for sys_id, (record, deleted) in acls.items():
        (us.deleted_acls if deleted else us.acls).append(record)
    live_acl_ids = {text_of(a, "sys_id") for a in us.acls}

    for acl_id, role, deleted in links.values():
        name = role_name(role)
        if deleted:
            us.deleted_links.append((acl_id, name))
        elif acl_id in live_acl_ids:
            us.acl_roles.setdefault(acl_id, []).append(name)
        elif acl_id:
            us.orphan_links.append((acl_id, name))
    for roles in us.acl_roles.values():
        roles.sort()

    us.contains = [(role_name(r), role_name(c)) for r, c, deleted in containment.values() if not deleted]
    return us, None


def acl_label(acl):
    name = text_of(acl, "name", "(unnamed)")
    operation = text_of(acl, "operation").lower()
    sys_id = text_of(acl, "sys_id", "(no sys_id)")
    return f'"{name}" [{operation or "no operation"}] {sys_id}'


def evaluate(acl, role_count):
    """Heuristic checks on one ACL. Returns a list of (level, message).

    role_count must be the number of LIVE role links; deleted links are
    not grants.

    These are 'worth a human look' signals, not a reimplementation of
    ServiceNow's evaluation engine: no role hierarchy, no dot-walk
    inheritance, no script-condition evaluation. Stated here so the
    output is not read as more authoritative than it is.
    """
    findings = []

    operation = text_of(acl, "operation").lower()
    label = acl_label(acl)

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


def load_contract(path):
    """Return (contract, error). The contract must name at least one ACL."""
    try:
        contract = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"ACL contract {path} could not be loaded: {exc}"
    acls = contract.get("acls") if isinstance(contract, dict) else None
    if not acls or not all(isinstance(a, dict) and a.get("name") and a.get("operation") for a in acls):
        return None, f"ACL contract {path} has no 'acls' entries with a name and operation."
    return contract, None


def reachable_roles(granted, contains):
    """Every role that satisfies a roles list, following role containment."""
    reach = set(granted)
    changed = True
    while changed:
        changed = False
        for parent, child in contains:
            if child in reach and parent not in reach:
                reach.add(parent)
                changed = True
    return reach


def check_contract(us, contract):
    """Compare live records against the contract. Returns [(level, message)]."""
    findings = []

    def describe(roles, condition):
        return f"roles {list(roles) or 'none'}, condition {condition or '(none)'!r}"

    # One table can legitimately carry several ACLs for the same operation
    # (rules 2 and 3 are both table reads), so an ACL is identified by its
    # full signature, not by name and operation alone.
    unmatched = list(us.acls)
    for entry in contract["acls"]:
        name, operation = entry["name"], entry["operation"].lower()
        want_roles = tuple(sorted(entry.get("roles", [])))
        want_condition = entry.get("condition", "")
        rule = f"rule {entry['rule']} " if "rule" in entry else ""
        want = f'"{name}" [{operation}]'

        match = next((acl for acl in unmatched
                      if text_of(acl, "name") == name
                      and text_of(acl, "operation").lower() == operation
                      and tuple(us.acl_roles.get(text_of(acl, "sys_id"), [])) == want_roles
                      and text_of(acl, "condition") == want_condition), None)
        if match is None:
            same_target = [acl for acl in unmatched
                           if text_of(acl, "name") == name and text_of(acl, "operation").lower() == operation]
            seen = "; ".join(
                f"{text_of(a, 'sys_id')} has "
                + describe(us.acl_roles.get(text_of(a, "sys_id"), []), text_of(a, "condition"))
                for a in same_target) or "no live ACL with that name and operation"
            findings.append(("error", f"Contract {rule}{want} with {describe(want_roles, want_condition)} "
                                      f"is not satisfied. Found: {seen}. Deleted role links are not "
                                      f"counted as grants."))
            continue
        unmatched.remove(match)
        label = acl_label(match)
        if not is_true(match, "active"):
            findings.append(("error", f"Contract {rule}{label} is not active."))
        if text_of(match, "script") and not entry.get("script_allowed", False):
            findings.append(("error", f"Contract {rule}{label} carries a script; the contract "
                                      f"expects a declarative rule."))

    for acl in unmatched:
        roles = us.acl_roles.get(text_of(acl, "sys_id"), [])
        findings.append(("error", f"{acl_label(acl)} with {describe(roles, text_of(acl, 'condition'))} "
                                  f"is a live ACL that the contract does not describe."))

    known_roles = set(us.roles.values())
    for entry in contract["acls"]:
        for role in entry.get("roles", []):
            if role not in known_roles:
                findings.append(("error", f"Contract role {role} is not defined by a live "
                                          f"sys_user_role record in this update set."))
                known_roles.add(role)

    nav_roles = contract.get("navigation_roles", [])
    if nav_roles and not us.navigation:
        findings.append(("error", "The contract requires navigation roles, but no application "
                                  "menu or module records were found. Failing closed."))
    for table, label, granted in us.navigation:
        reach = reachable_roles(granted, us.contains)
        for role in nav_roles:
            if role not in reach:
                findings.append(("error", f'{table} "{label}" requires {granted or "no role"}; '
                                          f"a user holding only {role} cannot open it."))

    return findings


def main(argv):
    parser = argparse.ArgumentParser(description="Audit ACLs in ServiceNow update-set XML exports.")
    parser.add_argument("patterns", nargs="*", default=["update-set/*.xml", "*.xml"],
                        help="Glob patterns for update-set XML files")
    parser.add_argument("--contract", default=str(DEFAULT_CONTRACT),
                        help="ACL contract JSON (default: %(default)s)")
    parser.add_argument("--no-contract", action="store_true",
                        help="Run the per-ACL heuristics only")
    args = parser.parse_args(argv[1:])

    contract = None
    if not args.no_contract:
        contract, error = load_contract(args.contract)
        if error:
            print(f"::error::{error} Failing closed rather than auditing without it.")
            return 2

    paths = []
    for pattern in args.patterns:
        paths.extend(sorted(glob.glob(pattern, recursive=True)))
    paths = [p for p in dict.fromkeys(paths) if Path(p).is_file()]

    if not paths:
        print(f"::error::No update-set XML matched {args.patterns}. Nothing was audited, "
              f"which is treated as a failure rather than a pass.")
        return 2

    total_acls = 0
    failures = warnings = notices = 0
    hard_error = False

    def report(path, level, message):
        nonlocal failures, warnings, notices
        # Annotated at file level deliberately. The records live inside
        # CDATA payloads, so any line number this script invented would
        # point at the wrong place. The ACL is identified by name,
        # operation and sys_id instead.
        print(f"::{level} file={path}::{message}")
        if level == "error":
            failures += 1
        elif level == "warning":
            warnings += 1
        else:
            notices += 1

    for path in paths:
        us, note = extract_records(path)

        if note:
            print(f"::error file={path}::{note}")
            hard_error = True
            continue

        if not us.acls:
            # THE FIX. The old implementation returned success here.
            print(f"::error file={path}::Parsed 0 live sys_security_acl records from this file. "
                  f"Either it contains no ACLs, or the export format changed and this "
                  f"audit can no longer read it. Failing closed rather than reporting a pass.")
            hard_error = True
            continue

        total_acls += len(us.acls)
        print(f"{path}: {len(us.acls)} live ACL record(s), {us.live_link_count} live role link(s), "
              f"{len(us.deleted_links)} deleted role link(s) ignored, "
              f"{len(us.deleted_acls)} deleted ACL(s) ignored")

        for acl_id, role in us.deleted_links:
            report(path, "notice", f"Role link {role} -> ACL {acl_id} is a DELETE record and was "
                                   f"not counted as a grant.")
        for acl in us.deleted_acls:
            report(path, "notice", f"{acl_label(acl)} is a DELETE record and was not audited.")
        for acl_id, role in us.orphan_links:
            report(path, "warning", f"Role link {role} -> ACL {acl_id} references an ACL that is "
                                    f"not live in this file, so it was not counted.")

        for acl in us.acls:
            role_count = len(us.acl_roles.get(text_of(acl, "sys_id"), []))
            for level, message in evaluate(acl, role_count):
                report(path, level, message)

        if contract is not None:
            for level, message in check_contract(us, contract):
                report(path, level, message)

    print(f"\nAudited {len(paths)} file(s), {total_acls} live ACL record(s): "
          f"{failures} failure, {warnings} warning, {notices} notice.")

    if hard_error:
        return 2
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
