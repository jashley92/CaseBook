# CaseBook — First Install (Windows Server 2022 + SQL Server 2022)

End-to-end procedure to stand up a fresh production instance. For ongoing operations
(backup/DR, key rotation, host hardening) see **[OPERATIONS.md](OPERATIONS.md)**; that runbook's
**Deploy-time Checklist** (§4) is the sign-off list for this install.

> Development uses zero-install SQLite and needs none of this — just
> `dotnet run --project src/IncidentManager.Web`. This document is production only.

---

## 0. Architecture in one paragraph

CaseBook is an ASP.NET Core **Blazor Server** app (.NET 10) hosted **in-process under IIS**, talking to
**SQL Server 2022** over **Windows integrated authentication** (no SQL passwords). Users authenticate
with **Windows Integrated Auth**; AD security groups map to the five app roles. Evidence blobs,
integrity seals, and generated reports live on an **ACL-restricted data volume outside the web root**.
The schema is created by **EF Core migrations** (a dedicated SQL Server migrations assembly).

---

## 1. Prerequisites

### 1.1 Server specifications

Baseline for a **small SOC** (roughly 5–30 analysts, low hundreds of cases/year — the
scale CaseBook is built for). These are starting points on modern virtual hardware; scale up
if your user count, evidence volume, or retention is larger. Separate app and DB hosts are
recommended (backup isolation, smaller blast radius), but the two roles **can** co-locate on a
single well-resourced host for the smallest deployments.

**Key sizing fact:** evidence and report **blobs live on the app host's data volume, not in
SQL** (only hashes/metadata are in the database). So the SQL data files stay small and steady,
while the **app data volume is the main thing that grows** — size it to your evidence retention.

| | Application / web host | Database host |
|---|---|---|
| **OS** | Windows Server 2022 (Standard/Datacenter) | Windows Server 2022 |
| **Server software** | IIS + **.NET 10 Hosting Bundle** | **SQL Server 2022 Standard** (Express is unsupported: 10 GB cap, no SQL Agent for backups) |
| **CPU** | 4 vCPU (2 minimum) | 4 vCPU |
| **RAM** | 8 GB minimum, **16 GB recommended** (Blazor Server holds a live circuit per active user in memory; report generation adds headroom) | **16 GB** (cap SQL "max server memory" to leave the OS ~2–4 GB) |
| **System disk** | 60 GB SSD (OS + .NET + published app) | 80 GB SSD (OS + SQL binaries) |
| **Data disk** | **Separate ACL'd volume, 100 GB+ SSD** for the data root (evidence / reports / seals / keys / DP-keys) — **expandable**; this is the growth driver | **Data (.mdf)** 50 GB + **Log (.ldf)** 20 GB SSD (FULL recovery grows the log between backups); backups to a **separate secured/offsite** target sized to retention (OPERATIONS.md §1) |
| **Network** | TLS 443 inbound; Kerberos to AD; outbound 1433 to SQL | 1433 from the app host; AD reachable |

Both hosts must be **domain-joined**. Use a **gMSA** for the app-pool identity (passwordless).
Virtual hardware is fine. RCSI is enabled on the database (read-heavy dashboards).

### 1.2 Accounts & AD (do these first — they have lead time)

- [ ] A **service account** for the app pool. **gMSA strongly preferred** (passwordless), e.g.
      `CONTOSO\svc-casebook$`. A normal domain service account works too (you'll supply its password).
- [ ] Five **AD security groups** for the roles (names are yours):
      Analysts, Incident Commanders, Leadership/Managers, Legal/Privacy, App Admins.
- [ ] If using a gMSA: install it on the web host — `Install-ADServiceAccount svc-casebook`.
- [ ] A **TLS certificate** for the site hostname installed in `LocalMachine\My` (note its thumbprint),
      **or** a TLS-terminating reverse proxy / load balancer in front.

### 1.3 Web host (Windows Server 2022)

- [ ] IIS with the features below, then the **.NET 10 Hosting Bundle** (installs the ASP.NET Core Module).
      Install the Hosting Bundle **after** IIS, then `iisreset`.

```powershell
Install-WindowsFeature Web-Server, Web-Windows-Auth, Web-Asp-Net45, Web-Net-Ext45, `
                       Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Mgmt-Console -IncludeManagementTools
# Then install the .NET 10 Hosting Bundle from https://dotnet.microsoft.com/download/dotnet/10.0
```

- [ ] To publish **on** the server, the **.NET 10 SDK** as well. Alternatively publish on a build box and
      copy the output — then run `Install-CaseBook.ps1` with the folder already populated.
- [ ] The `SqlServer` PowerShell module **or** `sqlcmd.exe` for the database step
      (`Install-Module SqlServer -Scope AllUsers`).

### 1.4 Database host (SQL Server 2022)

- [ ] SQL Server 2022, mixed or Windows auth (the app uses **Windows** auth).
- [ ] You have a login that is **sysadmin** on the instance to run the provisioning script once.
- [ ] Decide the data root and backup targets (OPERATIONS.md §1).

### 1.5 Prepare the answers file (recommended)

Both installers accept every setting either as **parameters** or from a **single answers file**
(`casebook.config.psd1`) you pass with **`-ConfigFile`**. The answers file is the simplest path:
fill it in once, copy it to both hosts, and each step becomes a one-liner. A parameter you also
pass on the command line always overrides the file.

The easiest way to produce it is the **generator**, which prompts for every value (with defaults,
a TLS-cert picker, and gMSA/AD checks) and writes the file for you:

```powershell
cd <repo>\deploy
.\New-CaseBookConfig.ps1        # answer the prompts -> writes .\casebook.config.psd1
```

Prefer to edit by hand? Copy **`casebook.config.template.psd1`** to `casebook.config.psd1` and fill it in.

Then **check it resolves before running the heavy steps** — on each host, run the readiness pass
(validates the service account + AD groups resolve, the TLS cert is present/valid, the paths are
sane, and SQL is reachable over Windows auth):

```powershell
.\Verify-Install.ps1 -ConfigFile .\casebook.config.psd1
```

Fix any **[FAIL]** before installing; **[WARN]** items are usually just "can't check that from
this host" (e.g. the web-host cert when run on the SQL box).

> The answers file names AD groups, hosts, and the service account — treat it as sensitive and
> don't commit it. It holds **no passwords**: a gMSA is passwordless, and a normal service
> account's password is prompted for securely at install time (never written to the file).

---

## 2. Provision the database

Run **on or near the SQL Server**, as the sysadmin account. This creates the database
(FULL recovery, RCSI on) and the app-pool identity's login/user with least privilege.

```powershell
cd <repo>\deploy
.\Install-Database.ps1 -ConfigFile .\casebook.config.psd1
```

Or pass the values directly instead of a config file:

```powershell
.\Install-Database.ps1 -SqlInstance SQLHOST\PROD -AppAccount "CONTOSO\svc-casebook$" -DbName CaseBook
```

- Default `-SchemaMode AppMigrates` grants the app account `db_owner` so the **app builds the schema on
  first start**. Prefer a DBA-applied schema? Use
  `-SchemaMode DbaApplies -ApplySchema` — the app account then gets only datareader/datawriter/EXECUTE and
  `sql/casebook-schema-sqlserver.sql` is applied now. (`-ApplySchema` is a runtime switch, not an
  answers-file value — pass it on the command line when you want the schema applied now.)
- Idempotent — safe to re-run.

---

## 3. Install the application

Run **on the web host, elevated** (Run as Administrator). Publishes the app, creates the data root,
writes `appsettings.Production.json`, creates the IIS app pool + site, enables Windows Auth, and sets ACLs.

Copy the same **`casebook.config.psd1`** you used for the database step onto this host, then:

```powershell
cd <repo>\deploy
.\Install-CaseBook.ps1 -ConfigFile .\casebook.config.psd1
# Domain service account (not a gMSA)? add the secure credential prompt:
.\Install-CaseBook.ps1 -ConfigFile .\casebook.config.psd1 -AppPoolCredential (Get-Credential)
```

Or pass every value directly instead of a config file:

```powershell
.\Install-CaseBook.ps1 `
  -AppPoolIdentity "CONTOSO\svc-casebook$" `
  -SitePath  D:\inetpub\casebook `
  -DataRoot  E:\CaseBookData `
  -Hostname  casebook.contoso.com `
  -SqlInstance SQLHOST\PROD -DbName CaseBook `
  -CertificateThumbprint AABBCCDDEEFF00112233445566778899AABBCCDD `
  -AdGroupAnalysts   SOC-Analysts `
  -AdGroupCommanders SOC-IncidentCommanders `
  -AdGroupLeadership SOC-Leadership `
  -AdGroupLegal      Legal-Privacy `
  -AdGroupAppAdmins  SOC-AppAdmins
```

- **gMSA**: omit `-AppPoolCredential`. **Domain service account**: add
  `-AppPoolCredential (Get-Credential)` and you'll be prompted securely (no password on the command line
  or in the answers file). `-SkipPublish` / `-AddNuGetOrgSource` are runtime switches too (below).
- **No cert yet**: omit `-CertificateThumbprint` to get an HTTP binding for a first smoke test, then
  re-run with the thumbprint (or terminate TLS at a proxy). Do not serve real data over plain HTTP.
- `-SitePath` (web root) and `-DataRoot` (evidence/seals/reports/keys/ops) are **deliberately separate**;
  keep the data root off the web root and in the backup + EDR scope.

### Publishing / NuGet restore

The install step runs `dotnet publish`, which restores NuGet packages. Two common snags:

- **`NU1100: Unable to resolve …` for every package** — the SDK has **no package source registered** (even
  when the box *can* reach nuget.org). The installer **preflights** this and stops with the exact fix before
  the slow publish. Check with `dotnet nuget list source`; if nuget.org is missing, add it:
  ```powershell
  dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org
  ```
  then re-run — or re-run with **`-AddNuGetOrgSource`** to have the installer register it for you. (Behind a
  proxy, also set `HTTP_PROXY`/`HTTPS_PROXY` for the shell. Sources are **per-user** — register them as the
  account that runs the install.)
- **Air-gapped host / no SDK** — publish on a machine **with** internet and the .NET 10 SDK
  (`dotnet publish src/IncidentManager.Web -c Release -o <folder>`), copy `<folder>` into `-SitePath`, and
  run the installer with **`-SkipPublish`** — it then does only IIS + config + ACLs.

---

## 4. Provision the integrity signing key (out of band)

Production must **not** let the app generate its own seal-signing key (OPERATIONS.md §2). Generate it on a
trusted admin workstation / HSM and install it to the path the config points at:

```
E:\CaseBookData\keys\seal-signing.pem
```

Restrict the file's ACL to the app-pool identity (read) and archive the **public** key + `KeyId`
separately so seals remain independently verifiable.

---

## 5. Verify

`Verify-Install.ps1` does two things — a **pre-install readiness** check from the answers file
(run it on each host *before* that host's step; see §1.5) and this **post-install smoke test**:

```powershell
cd <repo>\deploy
.\Verify-Install.ps1 -Url https://casebook.contoso.com/ -AppPoolName CaseBook
# (or pass -ConfigFile to reuse the answers file's AppPoolName, and/or re-run readiness)
```

Then, signed in as a mapped user:

- [ ] The dashboard loads; you can open **Administration** as an App Admin.
- [ ] **Integrity → "Verify now"** reports the chain **VALID**.
- [ ] Create a throwaway case; confirm it saves and appears in the audit trail. (Prod does **not**
      seed demo data — an empty case list on a fresh install is expected.)
- [ ] Generate a Word draft + locked PDF to confirm the reporting stack and store paths.

---

## 6. Post-install (hand off to OPERATIONS.md)

- [ ] Schedule SQL **backups** (full/diff/log) to a secured, encrypted, offsite target — §1.1.
- [ ] Wire the **backup-status JSON** so Diagnostics → Backup &amp; restore health reads *Fresh* — §1.3.1.
- [ ] Perform one **restore rehearsal** and confirm chain + prior-seal verification on the copy — §1.3.
- [ ] Confirm the evidence/seal/report dirs are in the **EDR** monitoring policy — §3.
- [ ] Walk the **Deploy-time Checklist** (§4) and record sign-off.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| App fails to start; log says *Auth:Mode is 'Dev' in Production* | `appsettings.Production.json` not deployed or environment isn't Production. The installer writes it and IIS defaults the environment to Production; confirm the file exists in the site root. |
| `500.19` (0x8007000d), Module *IIS Web Core*, and **no app log at all** | The **ASP.NET Core Module isn't registered** — IIS can't parse the `<aspNetCore>` section in `web.config`. It ships with the **.NET 10 Hosting Bundle**, *not* the SDK. Install the Hosting Bundle, `iisreset`, retry. Confirm with `Test-Path C:\Windows\System32\inetsrv\aspnetcorev2.dll`. (The installer now preflights this.) |
| `500.30` / `500.31` on first hit | ASP.NET Core Module can't start the app — usually a bad connection string, or the app can't write its `App_Data` folder under the web root (the installer now pre-creates it with Modify). Check the Windows **Application** event log and `logs\stdout`. |
| `401 Unauthorized` for everyone | Windows Auth not negotiating — missing **SPN** for the hostname, or Anonymous still enabled. Verify Kerberos SPNs and that the installer disabled Anonymous. |
| Login OK but *access denied* everywhere | The signed-in user isn't in any mapped AD group, or `RoleMapping:Groups` names don't match real groups. Fix the group names (config seeds roles on first run; thereafter manage in-app). |
| DB error at startup: *CREATE TABLE permission denied* | App account lacks DDL under `-SchemaMode AppMigrates`. Re-run the DB step, or switch to `DbaApplies` and apply `sql/casebook-schema-sqlserver.sql`. |
| Login failed for the app account | The SQL login/user wasn't created on this instance/db, or the app pool isn't actually running as that account. Re-run `Install-Database.ps1`; confirm the app-pool identity. |
