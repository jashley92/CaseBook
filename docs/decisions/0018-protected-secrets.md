# 0018. Secrets without CyberArk: entered in the app, or `@protected:` to a certificate

- **Status:** Accepted. Built as backlog item CAP-05. Configuration:
  [OPERATIONS.md §6](../operations/secrets.md#6-secret-management-f-19) and
  [integrations.md, Email](../operations/integrations.md#email-smtp).
- **Recorded:** 2026-10-18

## Context

Three configured values are credentials: the SIEM webhook token, the chat webhook URL and, once relays that refuse
anonymous senders had to be supported, the SMTP password. Until now each was a literal in
`appsettings.Production.json` or a `@cyberark:` reference ([0016](0016-key-custody-and-seal-copies.md), F-19). Many
sites have no CyberArk, so for them the only choice was plain text in a file that operators copy, diff and attach to
change tickets.

## Decision

### 1. The SMTP sign-in is entered in Administration, encrypted with Data Protection

The usual path needs no tool and no file edit. An administrator chooses none, username and password, or Windows (the
app-pool account) on the Email sign-in form. The password is write-only. It's encrypted with ASP.NET Core Data
Protection under its own purpose (`CaseBook.Secrets.Smtp.v1`), using the key ring CaseBook already keeps for
sessions (`DataProtection:KeyPath`, DPAPI-protected to the machine). It's stored as ciphertext in its own table
(`SmtpSignIns`), outside the configuration bundle, the settings list and the audit values. The audit trail records
who changed the sign-in, when, the mode, and whether the password was set, replaced or cleared. When the server's
configuration sets a sign-in, the server's configuration wins ([0007](0007-settings-split.md): security settings
belong to the server), and the form shows it read-only.

### 2. A configured secret can be `@protected:`, encrypted to a certificate in the store

For values that stay in the file, `@protected:v1:<thumbprint>:<base64>` is resolved through the same secret seam as
`@cyberark:`. A random AES-256-GCM key encrypts the secret. The key is wrapped to the certificate's RSA key with
OAEP-SHA256, and the version and thumbprint are the GCM associated data. `casebook-keytool protect-secret` makes a
value from the public key alone; `check-secret` checks one. This is the pattern the chain key's file already uses
(0016), with the same certificates.

### 3. One provider in front of both

`ProtectedSecretProvider` opens `@protected:` values and hands everything else to the passthrough or CyberArk, so it
works with CyberArk on or off, and no caller changed. Both paths fail closed: a value that won't open or decrypt is
unavailable, logged once without its content, and the dependent send is held or skipped. A secret is never replaced
by the text that names it.

## Alternatives considered

- **CyberArk only.** It isn't everywhere, and forcing it would leave those sites with plain text.
- **DPAPI-encrypted values in the file.** These are bound to one machine and one account. They break silently on a
  move or a farm, and there's nothing to back up beyond the machine itself.
- **A new key file for secrets.** That's new key material to protect and back up. The certificate store and the Data
  Protection key ring are already there, already ACL'd and already in the backup plan.
- **The SMTP password as an AppSettings row.** It would travel in the configuration bundle and show in the settings
  history and audit values unless every one of those paths learned an exception. A table of its own keeps it out by
  construction.

### 4. Follow-up (CAP-40): the chat webhook URL and the SIEM webhook token are entered the same way

Both can be entered in Administration as the SMTP password is: write-only, a Data Protection purpose each
(`CaseBook.Secrets.ChatWebhookUrl.v1`, `CaseBook.Secrets.SiemWebhookToken.v1`), audited without the value, 5403 on the
SIEM, and the server's configuration wins. They share one table, `StoredSecrets`, a row per secret keyed by the
configuration key it stands in for, since each is a single value; the SMTP sign-in keeps its own table, because its
password is one part of a sign-in with a mode and a username. A SIEM token that's set but won't resolve or decrypt now
stops the webhook's sends, where before the event went without an auth header: the same rule as the SMTP sign-in (never
a send without the credential that was asked for), and what §3 already said of the dependent send.

## Consequences

- The Data Protection key ring must be backed up with the database. Restored without it, the saved password doesn't
  decrypt, mail is held, and Diagnostics asks for the password again (§1 of OPERATIONS.md). The same holds for a saved
  chat URL (chat isn't posted) and SIEM token (the webhook sends nothing) (CAP-40).
- A renewed certificate means making the `@protected:` values again before the old certificate leaves the store.
- The app-pool account needs read on the certificate's private key, as it already does for the integrity
  certificates.
- Secrets aren't stronger than the server: anyone who can run code as the app-pool account can read them. This keeps
  them out of files and copies, not away from the server itself.
