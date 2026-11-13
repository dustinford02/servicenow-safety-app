"""Unit tests for tools/acl_audit.py. Standard library only.

    python3 -m unittest discover -s tools/tests -v
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import acl_audit  # noqa: E402

USER = ("u0000000000000000000000000000001", "x_test.user")
ADMIN = ("a0000000000000000000000000000001", "x_test.admin")


def role(role_ref):
    sys_id, name = role_ref
    return f"<sys_user_role><name>{name}</name><sys_id>{sys_id}</sys_id></sys_user_role>"


def acl(sys_id, operation, name="x_test_table", condition=""):
    cond = f"<condition>{condition}</condition>" if condition else "<condition/>"
    return (f"<sys_security_acl><active>true</active><admin_overrides>true</admin_overrides>"
            f"<advanced>false</advanced>{cond}<description>test</description><name>{name}</name>"
            f"<operation>{operation}</operation><script/><sys_id>{sys_id}</sys_id></sys_security_acl>")


def link(sys_id, acl_id, role_ref, action="INSERT_OR_UPDATE"):
    role_id, role_name = role_ref
    return (f'<sys_security_acl_role action="{action}"><sys_id>{sys_id}</sys_id>'
            f"<sys_security_acl>{acl_id}</sys_security_acl>"
            f'<sys_user_role display_value="{role_name}">{role_id}</sys_user_role></sys_security_acl_role>')


def menu(roles):
    return (f"<sys_app_application><roles>{roles}</roles><sys_id>m1</sys_id>"
            f"<title>Test</title></sys_app_application>")


def wrap(record, action="INSERT_OR_UPDATE", type_="Access Control"):
    """One <sys_update_xml>, shaped like a real export: the wrapper's action
    attribute stays INSERT_OR_UPDATE even when the <action> element is DELETE."""
    tag = record[1:record.index(">")].split()[0]
    if action == "DELETE":
        record = record.replace(f"<{tag}", f'<{tag} action="DELETE"', 1).replace(
            ' action="INSERT_OR_UPDATE"', "", 1)
    return (f'<sys_update_xml action="INSERT_OR_UPDATE"><action>{action}</action>'
            f"<payload><![CDATA[<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            f'<record_update table="{tag}">{record}</record_update>]]></payload>'
            f"<type>{type_}</type></sys_update_xml>")


def unload(*updates):
    return '<?xml version="1.0" encoding="UTF-8"?><unload>' + "".join(updates) + "</unload>"


CONTRACT = {
    "acls": [
        {"name": "x_test_table", "operation": "read", "roles": ["x_test.user"], "condition": ""},
        {"name": "x_test_table", "operation": "delete", "roles": ["x_test.admin"], "condition": ""},
    ],
    "navigation_roles": ["x_test.user", "x_test.admin"],
}


def compliant_records():
    return [
        wrap(role(USER), type_="Role"),
        wrap(role(ADMIN), type_="Role"),
        wrap(acl("acl_read", "read")),
        wrap(link("l1", "acl_read", USER), type_="Access Roles"),
        wrap(acl("acl_delete", "delete")),
        wrap(link("l2", "acl_delete", ADMIN), type_="Access Roles"),
        wrap(menu("x_test.user,x_test.admin"), type_="Application Menu"),
    ]


class AuditCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.contract = self.dir / "contract.json"
        self.contract.write_text(json.dumps(CONTRACT), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, text, name="set.xml"):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return path

    def run_main(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = acl_audit.main(["acl_audit.py", *map(str, args)])
        return code, out.getvalue()


class FailClosed(AuditCase):
    def test_no_matching_files_exits_2(self):
        code, out = self.run_main(self.dir / "nothing-*.xml", "--contract", self.contract)
        self.assertEqual(code, 2)
        self.assertIn("Nothing was audited", out)

    def test_update_set_with_zero_acls_exits_2(self):
        path = self.write(unload(wrap(role(USER), type_="Role")))
        code, out = self.run_main(path, "--contract", self.contract)
        self.assertEqual(code, 2)
        self.assertIn("Parsed 0 live sys_security_acl records", out)

    def test_unreadable_payload_is_not_a_pass(self):
        # The original aclLinter.js bug, inverted: records the audit cannot
        # see must fail, not pass.
        path = self.write(unload("<sys_update_xml><payload>not xml</payload></sys_update_xml>"))
        code, _ = self.run_main(path, "--no-contract")
        self.assertEqual(code, 2)

    def test_malformed_xml_exits_2(self):
        path = self.write("<unload><sys_update_xml>")
        code, out = self.run_main(path, "--no-contract")
        self.assertEqual(code, 2)
        self.assertIn("XML parse error", out)

    def test_missing_contract_exits_2(self):
        path = self.write(unload(*compliant_records()))
        code, out = self.run_main(path, "--contract", self.dir / "absent.json")
        self.assertEqual(code, 2)
        self.assertIn("could not be loaded", out)

    def test_all_acls_deleted_exits_2(self):
        path = self.write(unload(wrap(acl("acl_read", "read"), action="DELETE")))
        code, _ = self.run_main(path, "--no-contract")
        self.assertEqual(code, 2)


class DeletedRoleLinks(AuditCase):
    def test_delete_action_element_is_not_a_grant(self):
        # Only the <action> element says DELETE; the record carries no
        # action attribute and the wrapper attribute says INSERT_OR_UPDATE.
        deleted = ('<sys_update_xml action="INSERT_OR_UPDATE"><action>DELETE</action>'
                   '<payload><![CDATA[<record_update table="sys_security_acl_role">'
                   + link("l1", "acl_write", USER).replace(' action="INSERT_OR_UPDATE"', "")
                   + "</record_update>]]></payload></sys_update_xml>")
        path = self.write(unload(wrap(role(USER), type_="Role"), wrap(acl("acl_write", "write")), deleted))
        us, note = acl_audit.extract_records(path)
        self.assertIsNone(note)
        self.assertEqual(us.live_link_count, 0)
        self.assertEqual(us.deleted_links, [("acl_write", "x_test.user")])

    def test_acl_whose_only_link_is_deleted_fails(self):
        path = self.write(unload(
            wrap(role(USER), type_="Role"),
            wrap(acl("acl_write", "write")),
            wrap(link("l1", "acl_write", USER), action="DELETE", type_="Access Roles"),
        ))
        code, out = self.run_main(path, "--no-contract")
        self.assertEqual(code, 1)
        self.assertIn("is active with no roles", out)
        self.assertIn("0 live role link(s), 1 deleted role link(s) ignored", out)

    def test_flat_export_delete_attribute_is_honoured(self):
        path = self.write(unload(
            acl("acl_write", "write"),
            link("l1", "acl_write", USER, action="DELETE"),
        ))
        us, _ = acl_audit.extract_records(path)
        self.assertEqual(us.acl_roles, {})
        self.assertEqual(len(us.deleted_links), 1)

    def test_delete_wins_over_duplicate_insert(self):
        path = self.write(unload(
            acl("acl_write", "write"),
            link("l1", "acl_write", USER),
            link("l1", "acl_write", USER, action="DELETE"),
        ))
        us, _ = acl_audit.extract_records(path)
        self.assertEqual(us.live_link_count, 0)

    def test_deleted_extra_role_still_satisfies_contract(self):
        # Mirrors the real update set: user was removed from the delete rule.
        records = compliant_records() + [
            wrap(link("l3", "acl_delete", USER), action="DELETE", type_="Access Roles")]
        code, out = self.run_main(self.write(unload(*records)), "--contract", self.contract)
        self.assertEqual(code, 0, out)

    def test_live_extra_role_breaks_contract(self):
        records = compliant_records() + [wrap(link("l3", "acl_delete", USER), type_="Access Roles")]
        code, out = self.run_main(self.write(unload(*records)), "--contract", self.contract)
        self.assertEqual(code, 1)
        self.assertIn("is not satisfied", out)


class Contract(AuditCase):
    def test_compliant_set_passes(self):
        code, out = self.run_main(self.write(unload(*compliant_records())), "--contract", self.contract)
        self.assertEqual(code, 0, out)

    def test_missing_acl_fails(self):
        records = [r for r in compliant_records() if "acl_delete" not in r]
        code, out = self.run_main(self.write(unload(*records)), "--contract", self.contract)
        self.assertEqual(code, 1)
        self.assertIn('"x_test_table" [delete]', out)

    def test_unexpected_acl_fails(self):
        records = compliant_records() + [
            wrap(acl("acl_create", "create")),
            wrap(link("l9", "acl_create", USER), type_="Access Roles")]
        code, out = self.run_main(self.write(unload(*records)), "--contract", self.contract)
        self.assertEqual(code, 1)
        self.assertIn("contract does not describe", out)

    def test_menu_without_admin_role_fails(self):
        records = [r for r in compliant_records() if "sys_app_application" not in r]
        records.append(wrap(menu("x_test.user"), type_="Application Menu"))
        code, out = self.run_main(self.write(unload(*records)), "--contract", self.contract)
        self.assertEqual(code, 1)
        self.assertIn("a user holding only x_test.admin cannot open it", out)

    def test_role_containment_satisfies_navigation(self):
        records = [r for r in compliant_records() if "sys_app_application" not in r]
        records.append(wrap(menu("x_test.user"), type_="Application Menu"))
        records.append(wrap(
            f'<sys_user_role_contains><contains name="x_test.user">{USER[0]}</contains>'
            f'<role name="x_test.admin">{ADMIN[0]}</role><sys_id>c1</sys_id></sys_user_role_contains>',
            type_="Contains Role"))
        code, out = self.run_main(self.write(unload(*records)), "--contract", self.contract)
        self.assertEqual(code, 0, out)


class RepositoryUpdateSet(AuditCase):
    def test_committed_update_set_satisfies_committed_contract(self):
        code, out = self.run_main(REPO / "update-set" / "*.xml")
        self.assertEqual(code, 0, out)
        self.assertIn("8 live ACL record(s), 9 live role link(s), 2 deleted role link(s) ignored", out)


if __name__ == "__main__":
    unittest.main()
