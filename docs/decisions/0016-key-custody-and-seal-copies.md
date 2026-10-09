# 0016. Integrity keys from a file, the certificate store or CyberArk; seal copies outside CaseBook

- **Status:** Proposed. Closes the rest of security finding S-05 and backlog item F-05b; the work is backlog items
  F-23 to F-28.
- **Recorded:** 2026-10-09

## Context

[0002](0002-integrity-spine.md) makes the record tamper-evident with a hash-chained audit log and signed seals. Two
gaps remain (S-05):

- **The chain is unkeyed.** Someone who can write to the database can rewrite recent entries and recompute every
  hash after them. Only the next seal catches that, so the entries since the last seal (6 hours by default) are
  protected by database access control alone.
- **The seals live with CaseBook.** The signing key is a PEM file on the app server, and each seal is stored in the
  database and in an export folder on that server. Someone holding the key could re-sign a rewritten history, and
  someone holding the database could delete seals. Nothing outside CaseBook remembers what was sealed.

The usual answers are a hardware security module, write-once (WORM) storage and an RFC 3161 timestamp authority.
This organization has none of those. It does have CyberArk, Windows certificate services and XSIAM. And day one
should stay simple: an install with none of this configured has to work exactly as it does today.

## Decision

All of it is configured in the server's `appsettings.Production.json` (and the installer's answer file), never in
the in-app settings. Those live in the database, so the people this protects against could switch it off there
([0007](0007-settings-split.md)). The Integrity page and Administration → Diagnostics show what is in force,
read-only.

### 1. Where the signing key lives (F-23, F-24)

`Integrity:SigningKey:Source`:

| Source | How | Strength |
|---|---|---|
| `File` (default; today's behavior) | The PEM at `SigningKeyPath`, readable only by the app account | A copy of the server's disk includes the key |
| `CertificateStore` | A certificate in `LocalMachine\My` by thumbprint; Windows signs with it | Strongest when the key is marked non-exportable: the key can be used but never copied out, even by a server administrator |
| `CyberArk` | The PEM fetched at startup through the existing secret provider (`@cyberark:…`) and held only in memory | Central custody, rotation and an access log; whoever fully controls the app server while it runs could read it from memory |

Every seal already records the id of the key that signed it. **Seals verify by that key**: the current key, or a
retired public key kept in `Integrity:SigningKey:RetiredPublicKeys` (a folder of PEM public keys, which are not
secret). That makes rotating the key safe; today a rotation would make every earlier seal fail. F-24 comes first
for that reason.

### 2. A key in the chain hash (F-25), off by default

`Integrity:ChainKey:Enabled` (false by default), with `Source`:

- `CyberArk`: a 32-byte secret fetched at startup and held only in memory.
- `Certificate`: CaseBook generates the secret once, stores it encrypted to a certificate's public key
  (RSA-OAEP) under the data folder, and decrypts it at startup with the certificate's private key.

Entries are hashed with HMAC-SHA256 under that key. Each audit row records how it was hashed (a hash version and a
key id; one additive migration), so history written before the switch keeps its plain hash and still verifies.
Someone with only database access can no longer produce a chain that verifies, so the unsealed window closes
against them.

Turning it on is one-way in practice: keyed entries can only be checked while their key is available. If the key
is missing while keyed entries exist, the monitor raises the integrity alarm instead of skipping the check. Keys
rotate by id, and older keys are kept for verification (CyberArk's secret versions, or older wrapped files).

### 3. Copies of every seal outside CaseBook (F-26, F-27)

The copy is only worth something if the people who can change CaseBook's database don't also control it. So:

- **To the SIEM (F-26), on whenever the SIEM stream is configured.** Each seal goes out as security event **5004
  "Integrity seal recorded"** (sequence, chain-head hash, time, key id, signature) through the existing transports.
  XSIAM is administered by the SOC, not by whoever runs the SQL Server or the app server, and it keeps audit
  trails for years. A documented XQL query (and a suggested scheduled rule) compares the seals in a compliance
  bundle with the 5004 events: a missing or different seal is the alarm. A failed export to the folder is logged,
  shown in Diagnostics and alerted on (today it is silently swallowed).
- **Optional extras (F-27), each off unless configured:**
  - **An append-only share:** point `Integrity:ExportPath` at a share on a server that CaseBook's administrators
    don't administer, with NTFS rights that let the app account create files but not change or delete them. The
    installer documents the ACL; `Verify-Install` checks that a test file can be written but not overwritten.
  - **A seal digest by email** (`Integrity:SealCopies:EmailTo`) to a mailbox under Microsoft 365 retention or a
    litigation hold.
  - **RFC 3161 timestamps** (`Integrity:SealCopies:TimestampAuthorityUrl`), for an organization that later runs
    its own timestamp authority. Only an internal URL is accepted; CaseBook doesn't reach the internet
    ([0005](0005-no-outbound-ai.md)'s zero-egress stance).

SQL Server ledger tables ([OPERATIONS.md §7](../OPERATIONS.md#7-sql-server-ledger-e-10)) remain a complementary,
optional layer inside the database engine.

### 4. Status and setup (F-28)

A read-only card on the Integrity page and in Diagnostics shows the signing-key source and key id, the retired
keys held, whether the chain key is on (and its source and key id), and where seal copies go and when each last
succeeded. The installer's answer file gains the same keys, and `Verify-Install` checks that each configured source
resolves (the certificate exists and its key is usable; the CyberArk reference resolves).

## Alternatives considered

- **Switches in the in-app settings.** Easier to find, but stored in the database this defends against.
- **A hardware security module, WORM storage or a public timestamp authority.** Stronger, but not available here,
  and a public authority is outbound traffic. The design leaves room for each.
- **The certificate store for the chain key directly.** The store holds asymmetric keys, not raw secrets; wrapping
  the secret with a certificate gets the same custody.
- **Keying the chain instead of sealing.** The key sits with the app either way; seals copied off the box are the
  stronger anchor. Both together close different gaps.

## Consequences

- Nothing changes for an install that configures none of it, except that seals also reach the SIEM when a stream
  is set up.
- The chain key adds a dependency at startup: with it on, CaseBook needs the key to check keyed history, and losing
  the key means the per-row check can't run for those entries (seals still prove they're intact). The operations
  guide must cover backing up the certificate or the CyberArk secret before turning it on.
- The examiner guide in the compliance bundle (`VERIFY.txt`) gains the HMAC check and the XQL comparison.
- An attacker now needs CaseBook's database **and** the key custody **and** XSIAM to rewrite history unnoticed.

## Order of work

F-24 (retired keys) → F-26 (seals to the SIEM) → F-23 (signing-key sources) → F-25 (chain key) → F-28 (status and
installer, alongside each) → F-27 (optional extras).
