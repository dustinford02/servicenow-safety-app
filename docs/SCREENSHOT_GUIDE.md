# Screenshot Guide

Screenshots have to be captured manually. This is the shot list, in the order that
tells the story best, with the redaction rules that apply to all of them.

---

## Redaction rules, applied to every image before committing

1. **Crop out the browser address bar.** It contains the instance URL, which is an
   instance identifier and should not appear in a public repository.
2. **Check the page for the instance name** appearing in banners, breadcrumbs, or
   the browser tab title. Crop or blur it.
3. **Sample records use ServiceNow's shipped demo users** (Abel Tuter, Fred Luddy,
   Beth Anglin). These are fictional and safe to show. Do not substitute real names.
4. **No real email addresses, phone numbers, or personal data** in any frame.

A useful habit: capture the content area only, not the whole browser window.

---

## The shot list

Eight images. Numbered filenames keep them ordered in the repository.

### `01-application-record.png`
The Custom Application record for Safety.
**Shows:** scope `x_2190973_safety`, version 1.0.0, the user role, JavaScript mode.
**Why:** establishes this is a properly scoped application, not global-scope work.

### `02-table-definition.png`
The Safety Issue table record.
**Shows:** table name, label, and that it extends nothing.
**Why:** supports the standalone-table decision discussed in the design rationale.

### `03-table-fields.png`
The dictionary entries for the table, or the field list in Studio.
**Shows:** `assigned_to` as a reference to `sys_user`, `manager_notes` as a string.
**Why:** reference fields are what make the row-level condition possible.

### `04-access-controls-list.png`
The access control list filtered to `x_2190973_safety`.
**Shows:** all seven rules, their operations, and which carry conditions.
**Why:** this is the single most important image in the set. It shows per-operation
rules and the field-level rule in one frame.

### `05-acl-row-level-condition.png`
The `read` access control that carries the dynamic condition, opened.
**Shows:** the condition builder with `Assigned to` `is` `(dynamic) Me`, and the
role requirement beneath it.
**Why:** demonstrates declarative row-level security rather than a script.

### `06-acl-field-level.png`
The `manager_notes` field-level read rule, opened.
**Shows:** the name in `table.field` form and the admin role requirement.
**Why:** demonstrates field-level control and, with image 04, the table-then-field
relationship.

### `07-list-as-admin.png`
The Safety Issues list while logged in as an administrator.
**Shows:** all four records, `manager_notes` visible.
**Why:** the "before" half of the security demonstration.

### `08-list-as-user.png`
The same list while **impersonating** a user holding only
`x_2190973_safety.user`, with that user set as `assigned_to` on some records.
**Shows:** a filtered subset of records, `manager_notes` absent.
**Why:** the "after" half, and the payoff. Images 07 and 08 side by side prove the
security model works rather than merely asserting it.

---

## Producing images 07 and 08 properly

This pair is the reason the repository is worth looking at, so it is worth setting
up correctly.

1. Grant `x_2190973_safety.user` to a demo user, for example Abel Tuter.
2. Confirm that user is `assigned_to` on some but not all of the four records.
3. Capture image 07 as an administrator.
4. Use **Impersonate User** to become that demo user. Do not reset their password
   and log in as them; impersonation is the correct mechanism and it is logged.
5. Capture image 08.
6. End the impersonation.

If image 08 looks identical to image 07, the rules are not doing what the
documentation claims. That is worth discovering before a reviewer does.

---

## Adding them to the README

Once captured, reference them from the README near the relevant section:

```markdown
![Access controls](screenshots/04-access-controls-list.png)
```

The two-image comparison is worth placing directly beneath the security model
table, where the claim it substantiates is made.
