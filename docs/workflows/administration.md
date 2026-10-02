# Administration workflows

Everything under **Administration** needs the `Administer` permission (SysAdmin by default). Every change is
audited and hash-chained, and most take effect without a restart. Server-side settings (connection strings,
authentication, key paths, SIEM, CyberArk) aren't editable here; they're shown read-only. See
[operations/configuration.md](../operations/configuration.md).

![Administration](../screenshots/admin-settings.png)

## The admin areas

| Area | Route | What you can do |
|---|---|---|
| Identity & branding | `/admin` | Organization and team name, time zone, default jurisdictions, accent and ink colors, report logo |
| Reports | `/admin/settings/reporting` | Report defaults (TLP, defanging, milestones, late-entry notes, separate approver, lessons legend), the section-layout designer, report profiles, the Word template library |
| Notifications | `/admin/settings/notifications` | Email on/off, sender, distributions, reminder scans and their timing, mandatory types, chat routing, base URL; the delivery-readiness panel and a test email |
| Email templates | `/admin/email-templates` | Subject and body of every notification email, with preview (the branded shell is fixed) |
| Integrations | `/admin/settings/integrations` | Detection-source label and link template, VirusTotal link template |
| Regulatory deadlines | `/admin/settings/regulatory-deadlines` | Deadline clock on/off, start basis, default window, per-jurisdiction rules |
| Governance & security | `/admin/settings/governance` | Retention (shown, unused), integrity (auto-seal, evidence re-hash), access logging scope and coalescing, idle timeout, two-person legal-hold release |
| Case templates | `/admin/templates` | Playbooks: defaults for the new-case form and steps that become tasks |
| Stage gates | `/admin/gates` | One gate per trigger: requirements, blocking or advisory, minimum reason length |
| Taxonomy labels | `/admin/taxonomy` | Rename, hide or reorder display labels for six lists: classifications, phases, entity types, dispositions, timeline entry types and relationship types (display only; stored values don't change). Severity labels are under Response & SLA |
| Data elements | `/admin/data-elements` | Personal-data categories and their notification jurisdictions; archive or (if unused) delete |
| Response & SLA | `/admin/settings/sla` | SLA targets per severity, breach overrides, at-risk threshold, severity labels |
| Roles & access | `/admin/roles` | Custom roles (from the eight permissions) and AD group mappings |
| API tokens | `/admin/api-tokens` | System tokens for machine producers |
| Server configuration | `/admin/settings/server` | Read-only view of server-side settings (secrets as present or absent) |
| Setting sources | `/admin/settings/source` | Each setting's effective value and where it comes from |
| Configuration bundle | `/admin/config-bundle` | Export, diff and import editable configuration |
| Diagnostics | `/admin/settings/diagnostics` | Backup and restore freshness, evidence-integrity status, CyberArk resolution health, SIEM test event, writable-path checks |
| Style guide | `/admin/style` | Live design-system reference for developers |
| Access log | `/access-log` (main navigation) | Who read which case or downloaded what |

## Editing settings

1. Open a section. Each card shows its settings; changed values are marked "Unsaved changes".
2. **Save changes** in the bar at the bottom of the section (or *Discard*). Leaving with unsaved changes asks
   first.
3. The service checks each value against the catalog (type, range, options), writes an audited `AppSetting`
   row, reloads configuration and emits SIEM 5403.

Two things to know: the form shows the **catalog default** where no override exists, not the value from your
server files (check *Setting sources*); and **clearing a number restores the file value**, so enter `0` to turn
something off.

## Roles and AD groups

- **System roles** (Analyst, IncidentCommander, Manager, LegalPrivacy, SysAdmin) are locked; their permissions
  are reset to code on every start.
- **Custom roles**: name, description and any combination of the eight permissions.
- **Mappings**: an AD group name (or SID) to a role; a group can map to several roles.
- Safeguards: the last role holding `Administer` can't lose it or be deleted; removing a mapping says what it
  will do. Deleting a role removes its mappings.
- Changes reach signed-in users within about two minutes. New AD group *membership* needs a new Windows logon.
- SIEM 5401 (roles) and 5402 (mappings).
- The installer seeds mappings from `RoleMapping:Groups` only on first start; afterwards they're managed here.

![Roles](../screenshots/roles-access.png)

## Case templates (playbooks)

A template has a name, description, active flag, sort order, optional default classification and severity,
data-type defaults, summary prompts, and ordered steps (title, description, owner hint, due offset in hours,
task kind). On the new-case form it pre-fills values and turns its summary text into prompts. After creation, or
later through *Apply playbook*, its steps become tasks. Editing a template replaces its steps; tasks already
created aren't changed. Five starter templates are seeded: Phishing wave, Ransomware, BEC / wire fraud, Lost /
stolen device, Third-party / vendor breach.

## Stage gates

See [governance.md](governance.md#stage-gates) for how gates work. Here you add requirements (a machine check
from the registry, with a number where it takes one, or an attestation's wording), mark each blocking or
advisory, order them, set a minimum reason length, and activate the gate. Only one gate per trigger can be
active. Gate edits don't change past passages, which recorded their own outcome.

## Data elements and notification rules

- **Data elements** are the personal-data categories an impact assessment records (13 system ones, such as SSN,
  payment card and medical information). Each has a stable key (stored on cases, never renamed), a label you can
  change, a sort order, and **notification jurisdictions** (`US, NY`) that drive the deadline clock. System
  elements can be archived but not deleted; custom ones can be deleted only if no case uses them.
- **Notification rules** set the window per jurisdiction code (NY and US, 72 hours, are seeded). System rules
  can't be deleted.

![Data elements](../screenshots/data-elements.png)

## API tokens

System tokens: a name (unique among active tokens), the roles they act with, and a required expiry (up to 365
days). The token is shown once. Revoke at any time. Personal tokens are created by each user from the account
menu. See [API.md](../API.md).

## Configuration bundle

Moves editable configuration between instances (test to production, a new instance from a baseline), or
snapshots it for comparison with a revised incident response plan.

- **Export** (`/export/config-bundle.json`): editable settings and taxonomy labels, roles, AD mappings, case
  templates, stage gates, report profiles with their Word templates, data elements and notification rules,
  signed with the instance's seal key. Email-template wording isn't included. Recorded in the audit chain.
- **Import** (up to 64 MB): the signature is checked against the public key **inside the file**, and the page
  says whether that key is this instance's. A valid signature is required: the page won't offer Apply without
  one, and `ConfigBundleService.ImportAsync` itself refuses a bundle whose signature doesn't verify. A diff
  shows what would change. Import adds and updates; it never deletes, and never changes system roles'
  permissions. Every change is audited (SIEM 5401–5403).
- Never included: cases, evidence, the audit trail, server-side configuration.

A valid signature proves the file wasn't altered after signing, not who made it. Check the key id before
importing a bundle from elsewhere ([known issues](../reference/known-issues.md#security)).

## Integrity operations

On the **Integrity & audit** page (any `ViewCases` user can verify; sealing needs `Administer`):

- **Verify now**: checks the whole chain and the latest seal (shared, at most once a minute).
- **Seal now**: signs the current chain head.
- **Audit trail**: filter by case, actor, action, entity and date; export a case's trail.
- **Compliance bundle**: for a date range.
- SQL Server ledger status, when enabled.

If the red integrity banner appears, follow [troubleshooting](../operations/troubleshooting.md#integrity-alarm-5001).

## Access log

`/access-log`: who opened which case and who downloaded which artifact or export, grouped into view sessions
(`Access:CoalesceWindowMinutes`), filterable by actor, case, type, restricted-only and date, with a CSV export.
`Access:LogScope` controls what's recorded (Off, RestrictedOnly, All). It's outside the audit chain and can be
pruned. Leadership also sees a "Viewed by" panel on each case's Audit tab.
