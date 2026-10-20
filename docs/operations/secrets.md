# Secret management

Section 6 of the [operations guide](../OPERATIONS.md), which keeps the deploy-time checklist and the host controls. Section numbers are kept, so "OPERATIONS.md section 6" in the app and the scripts means this page.

## 6. Secret Management (F-19)

App secrets read from configuration (the SIEM webhook `Token`, the chat `Chat:Webhook:WebhookUrl` and, CAP-05, the
SMTP password `Email:SmtpPassword`; connection strings, `Agenda:FeedKey` and the other SMTP settings must be
literals or environment variables) needn't be kept in plain text. Each is resolved at runtime through one seam, so a
value may be written three ways, chosen per value:

**The SMTP password is usually entered in the app instead** (Administration → Notifications → Email
sign-in): it's encrypted with Data Protection and kept in the database, with no keytool step. It's write-only, its
changes are audited, and it needs the Data Protection key ring backed up with the database (§1). Setting
`Email:SmtpUsername`/`SmtpPassword` or `Email:SmtpUseDefaultCredentials` in the file, as below, overrides the form
([integrations.md, Email](integrations.md#email-smtp)). Integrated Windows sign-in as the app-pool gMSA
(`Email:SmtpUseDefaultCredentials`, or *Windows* on the form) needs no password at all.

**The chat webhook URL and the SIEM webhook token can be entered in the app too** (CAP-40): Settings → Notifications →
Team chat webhook, and Server configuration → SIEM webhook token. They're kept as the SMTP password is (Data Protection,
a purpose each, the `StoredSecrets` table), write-only and audited, with the same key-ring backup (§1). A value set in
the file, in any of the three forms below, wins and the card shows it read-only. Either way, a SIEM token that's set
but won't resolve or decrypt stops the webhook's sends rather than sending them unauthenticated
([integrations.md, SIEM](integrations.md#siem-security-event-stream)).

**How a secret is selected**

- **Literal (default):** the configured value is the secret, exactly as before. For the SMTP password,
  Diagnostics warns that it's plain text.
- **Protected (`@protected:`, CAP-05, [ADR 0018](../decisions/0018-protected-secrets.md)):** the secret encrypted to a
  certificate in `LocalMachine\My` whose private key the app-pool account can read: no CyberArk, and no new key
  material in the file. Make the value on the server with `deploy\keytool\casebook-keytool protect-secret --cert
  <thumbprint>` (or `--site <site folder>` to use the site's evidence, chain-key or signing certificate); it asks for
  the secret twice without echo and prints only `@protected:v1:<thumbprint>:<data>`. Check one with
  `casebook-keytool check-secret <value>` (OK or why not; never the secret). It works whether CyberArk is on or off.
  A value that won't open (the certificate removed or renewed, its key unreadable, the value changed) is unavailable:
  logged once by thumbprint, never the content. When the certificate is renewed, make the values again for the new
  one before removing the old.
- **Reference:** a value of the form `@cyberark:Safe=<safe>;Object=<object>` (any `;`-separated CCP query
  parameters — `Safe`, `Folder`, `Object`, …) is fetched from **CyberArk Central Credential Provider (CCP /
  AIMWebService)** by **AppID + query**. The install-wide **AppID** comes from config, not the reference, so a
  reference names only *where* the secret is, never a credential. The rest of this section is about CyberArk; it's
  opt-in, and nothing changes until you move a specific secret to it.

Example — move the SIEM webhook token to CyberArk:

```jsonc
"Siem":    { "Webhook": { "Enabled": true, "Url": "https://collector...",
                          "Token": "@cyberark:Safe=SIEM;Object=CaseBook-Webhook-Token" } },
"Secrets": { "CyberArk": { "Enabled": true,
                          "BaseUrl": "https://ccp.corp.example/AIMWebService",
                          "AppId":   "CaseBook",
                          "ClientCertificateThumbprint": "‹thumbprint of a cert in LocalMachine\\My›",
                          "CacheTtlSeconds": 300, "FailClosed": true } }
```

**Configuration (`Secrets:CyberArk`, server-side only)**

| Key | Meaning | Default |
|-----|---------|---------|
| `Enabled` | Master switch. Off → all values are literals; a `@cyberark:` reference fails **closed** | `false` |
| `BaseUrl` | AIMWebService base URL. **Must be HTTPS** | `""` |
| `AppId` | CCP Application ID this app is provisioned as | `""` |
| `ClientCertificateThumbprint` | Optional client cert (in `LocalMachine\My`) for mutual TLS | `""` |
| `CacheTtlSeconds` | How long a fetched secret is cached (supports rotation without a restart) | `300` |
| `TimeoutSeconds` | Per-request timeout to CCP | `5` |
| `FailClosed` | On a CCP error: `true` → resolve to unavailable (safe degrade); `false` → serve the last-known-good cached value (never a plaintext-config fallback) | `true` |

**Authentication to CCP — who configures what.** There is **no CCP password to store** — that is the point
of CCP. The **CyberArk admin** decides how this application authenticates when they define its **Application
(AppID)** in the Vault, choosing any combination of: a **client certificate**, an **Allowed Machines**
list (source **IP address** / hostname), and/or the requesting **OS user**. CaseBook simply *presents* an
identity on each call; CCP accepts or rejects it against the AppID's rules. So most of the setup is on the
CyberArk side, and CaseBook's config is deliberately tiny. What you do here depends on the method(s) the
AppID requires:

| Authentication method (set on the CCP **AppID** by the CyberArk admin) | What CaseBook must do |
|---|---|
| **Client certificate** (whether the AppID marks it *required* or *optional*) | Install the cert in **`LocalMachine\My`**, grant the **app-pool identity read on its private key**, and set **`ClientCertificateThumbprint`**. This is the only auth method that needs a CaseBook config value. |
| **Allowed Machines — source IP / hostname** | **Nothing in config.** Ensure the web host reaches CCP from the **IP/hostname the admin allow-listed** — mind NAT, proxies, and multi-homed egress (the IP CCP *sees* is what matters, not the host's local IP). |
| **OS user** | **Nothing in config.** Run the CaseBook app pool under the **identity the admin allow-listed** — i.e. the gMSA / service account from [INSTALL.md §1.2](../INSTALL.md); that account is the OS user CCP will see. |

Notes:

- **"Cert required" is a CCP-side switch, not a CaseBook one.** CaseBook attaches a client cert **only when
  `ClientCertificateThumbprint` is set**; if the AppID requires a cert and the thumbprint is blank (or the
  cert can't be loaded), every fetch fails closed and the Diagnostics health panel shows *Last attempt
  failed*. Conversely, setting a thumbprint the AppID doesn't expect is harmless — CCP ignores it.
- **Methods combine (defense in depth).** A common hardened setup is *client cert **and** Allowed-Machines
  IP* — the admin sets both on the AppID; CaseBook sets the thumbprint and you make sure the host egresses
  from the allow-listed IP. No extra CaseBook config for the IP half.
- **App identity is set once, in the installer.** The app-pool identity (which drives both *OS user* and,
  via the host, *source IP*) is `AppPoolIdentity` from `Install-CaseBook.ps1` / the answers file — so the
  account and host you give CyberArk to allow-list are the ones the install already uses.
- If the AppID authenticates **only** by Allowed-Machines and/or OS user, leave `ClientCertificateThumbprint`
  blank — that is a valid, fully-supported configuration.

**Failure behaviour.** A reference that cannot be resolved returns **unavailable** — never the reference
text — so a caller treats it as "no secret". For the webhook that means the event is sent **without** an
auth header (and the collector will reject it) rather than leaking a bogus token; the failure is logged.
With `FailClosed=false`, a transient CCP outage instead serves the **last successfully fetched** value past
its TTL, so a working integration is not dropped by a blip.

**Admin visibility (read-only).** Secrets are **never editable in the app** — this stays host-side config.
Two read-only views help operators confirm it is wired up and working:
- **Administration → Server configuration** shows a *Secret store — CyberArk CCP* row with status badges
  only (Enabled/Disabled · endpoint configured · AppID set · client-cert vs machine/OS-user auth) — never a
  value.
- **Administration → Diagnostics → Secret resolution (CyberArk)** shows live health: overall status
  (Healthy / Last attempt failed / No activity), the **last success** and **last error** (timestamp, the
  reference *location*, and a safe reason such as `HTTP 403 (APPAP004E)` — never the secret), and running
  success/failure counts. It is in-memory and resets on restart. A persistent *Last attempt failed* here is
  the first place to look if an integration that depends on a CyberArk-backed secret stops authenticating.

**Candidates.** Applied to `Siem:Webhook:Token`, `Chat:Webhook:WebhookUrl` and `Email:SmtpPassword` (CAP-05); the first
two can be entered in Administration instead (CAP-40). Any future
config-borne credential should resolve through the same seam, which gives it `@protected:` too. The **seal signing key** (F-05b) and **Always-Encrypted column keys**
(F-14) are noted as candidates but generally prefer the Windows certificate store / HSM over CCP.
