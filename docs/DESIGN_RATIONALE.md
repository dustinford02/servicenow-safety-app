# Design Rationale

Decisions made while building this application, the alternatives considered, and
where I would do it differently.

---

## 1. A standalone table rather than extending Task

**Decision.** `x_2190973_safety_safety_issue` extends nothing. It is a base table.

**The alternative.** ServiceNow's `task` table is the parent of `incident`,
`problem`, `change_request`, and `sc_req_item`. Extending it would have delivered,
at no cost, a number, assignment group, state and priority fields, work notes,
approval support, and compatibility with Service Level Agreements. For anything
representing work a person performs, extending `task` is normally the correct
answer, and a safety issue plausibly qualifies.

**Why I did not.** I wanted the access control model to be legible in isolation.
Extending `task` inherits its access controls as well as its fields, which means
the effective permissions on a record are the product of rules I wrote and rules
that shipped with the platform. For an artifact whose purpose is to demonstrate
that I can reason about ACL evaluation, that inheritance would have obscured
exactly the thing I was trying to show.

**Where the argument cuts against me.** If this were a real application, the
inheritance would be a feature rather than a complication, and rebuilding
assignment and state by hand would be waste. A reviewer who says "you should have
extended Task" is not wrong about production; they are applying a production
standard to a demonstration artifact. I would extend `task` if I built this again
for use rather than for illustration.

---

## 2. Two roles rather than one

**Decision.** `x_2190973_safety.user` and `x_2190973_safety.admin`.

App Engine Studio generates a single user role by default. A single role cannot
express the central requirement here, which is that managers see something ordinary
users do not. The second role exists specifically so that the `manager_notes` field
has something to be restricted to.

Roles are granted to groups in practice, not directly to users, so that membership
is auditable and revocable in one place. This application defines the roles; it
does not prescribe the groups, because group structure belongs to the organization
deploying it rather than to the application.

---

## 3. Declarative conditions rather than scripted ACLs

**Decision.** Row-level security uses a dynamic condition on `assigned_to`
evaluated against the current user, not a scripted access control.

An access control evaluates its roles, then its condition, then its script, and all
three must pass. A script would have worked. It would also have been less readable,
harder for another administrator to audit, and something to re-examine at every
upgrade. The platform offers a declarative way to express "records assigned to the
person asking," so I used it.

The general principle I was applying: configure before you customize. Scripting is
the tool you reach for when the declarative option genuinely cannot express the
requirement, and it should be documented as technical debt when you do.

---

## 4. Separate rules per operation

**Decision.** Seven access controls rather than a smaller number of broader ones.

Create, read, write, and delete are distinct operations. A requirement such as
"ordinary users may read and edit their own issues, managers may do anything,
nobody but a manager may delete" decomposes into exactly the rules built here.
Attempting to compress them would either grant more than intended or require
scripting to re-separate what the model already separates cleanly.

The delete rule is deliberately admin-only and unconditional. Allowing users to
delete their own records would have been defensible, but destructive operations are
where I would rather be too restrictive than too permissive by default.

---

## 5. Field-level control on `manager_notes`

**Decision.** A single field-level read rule restricting `manager_notes` to the
admin role.

This is the rule that made the application worth building. Field-level access
controls in ServiceNow are evaluated *after* table-level ones, and only if a
table-level rule has already granted access. A field rule sitting behind a table
that grants nothing is unreachable and the access simply defaults to denied.

The practical consequence, and the thing I wanted to prove I understood: making a
field visible to a group requires ensuring the table is readable by them first, and
making a field *invisible* requires no table change at all, only the field rule.
The asymmetry catches people out.

An access control naming a specific field is evaluated before a wildcard rule
covering the rest of the table's fields, which is why one specific rule is
sufficient here and no wildcard was needed.

---

## 6. The access control I deleted

The application file history contains a deleted field-level access control.

I built a field rule first, tested it by impersonating a user holding only
`x_2190973_safety.user`, and found the field still behaved as before. The rule I
had written was not reaching evaluation in the way I assumed. Rebuilding it against
the correct table-then-field ordering produced rule 7 as it now stands.

I have left the deletion in the history rather than rewriting it away. A record of
having tested something and found it wrong is more informative than a clean history
that shows only the final state, and this specific mistake is one of the most
commonly described in ServiceNow access control material. Making it myself, in a
lab, is considerably cheaper than making it in production.

---

## 7. Publishing to a named update set

**Decision.** The application was published to a named update set rather than
relying on whatever had been captured during development.

All development work in this application was captured into the Default update set
for the scope. Work captured in Default cannot be transferred to another instance,
which would have made the application unpackageable and this repository impossible.

Publishing an application to an update set captures the complete application by
definition rather than by capture history, which sidesteps the problem entirely.
The habit this taught me, and the one that matters in a real environment: select
your update set before you begin configuring, not after.

---

## What I would build next

In rough order of what each would demonstrate:

1. **A Flow Designer flow** routing new issues to a manager for approval. This is
   the largest gap in the current artifact and the most commonly expected skill.
2. **A business rule** enforcing a data rule regardless of entry path. Access
   controls and UI configuration do not constrain records arriving by import or web
   service; a server-side rule does.
3. **A record producer** giving reporters a plain-language intake form rather than
   the raw table form.
4. **A REST integration**, inbound or outbound, to demonstrate the platform talking
   to something outside itself.
5. **Reporting**, at minimum an issues-by-assignee breakdown on a dashboard.

Items 1 through 4 are absent from the current build, which the README states
directly rather than leaving to inference.
