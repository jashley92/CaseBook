# 0017. Evidence and reports encrypted at rest, with a key that can't be lost

- **Status:** Accepted. Built as backlog item PROD-57. Configuration and procedures:
  [OPERATIONS.md §2, Evidence key](../OPERATIONS.md#evidence-key-encryption-at-rest-backups-and-recovery-prod-57).
- **Recorded:** 2026-10-17

## Context

Evidence is stored as uploaded, in files with random names outside the web root
([0008](0008-blobs-on-disk.md)). Three problems follow:

- **Antivirus deletes malware samples.** The server's endpoint protection quarantines a sample as it's written, or
  when the evidence re-check reads it. The evidence, and its chain of custody, are gone.
- **A copied disk or backup exposes everything**, evidence and generated reports alike.
- **An antivirus exclusion is the usual workaround**, and it leaves the store unwatched.

Encrypting at rest fixes all three. But the key then holds every file: losing it loses all the evidence, which is
worse than any of the problems above. So the design is mostly about the key: where its server copy is protected,
how many independent backups exist, how they're tested, and what CaseBook does when the key isn't there.

## Decision

### 1. One master key, its server copy protected by the integrity keys already configured

CaseBook makes one random 256-bit evidence key. Every file has its own random file key, stored in the file's header
encrypted under the evidence key. The evidence key is never written anywhere in the clear. Its server copy is
protected by what the site already has for the audit chain ([0016](0016-key-custody-and-seal-copies.md)), in this
order:

1. `Storage:Encryption:CertificateThumbprint`, for a site that wants evidence kept apart from the audit chain;
2. the chain key's certificate;
3. the seal-signing certificate in the certificate store;
4. the chain key from CyberArk: the evidence key is encrypted under a key derived from it (HKDF), so the vault's
   own backup covers it;
5. none of these: encryption stays off, and Diagnostics says what to configure.

No new certificate or vault object is needed, and a certificate renewal is handled at the next check: when the
old certificate is still in the store, the key is re-encrypted to the new one. Only the envelope changes, never a
file.

### 2. Four independent backups

- **Recovery certificates** (`Storage:Encryption:RecoveryCertificates`): public `.cer` files. The evidence key, and
  the chain key when it's on, are also encrypted to each. Their private keys stay offline (a smartcard, or a PFX in
  a safe), so any one of them recovers the key without the server. Two, with two custodians, is the recommended
  setup.
- **Split shares** (`casebook-keytool split`): the key split 3 of 5 (by default) with Shamir's scheme, as short
  checksummed strings for paper or USB. Any three rebuild it; two reveal nothing. CaseBook records that shares were
  issued, never the shares.
- **The envelope in three places:** the keys folder, the database (`KeyEnvelopes`, so database backups carry it), and
  beside the evidence (`<store>\.key\evidence-key.json`, so the files and the key id they need travel together).
  A missing or damaged copy is rewritten from a good one. The copies are ciphertext, useless without a certificate
  or the shares.
- **CyberArk**, when the chain key comes from there (item 4 above).

Encryption doesn't start until there is at least one recovery certificate or the shares have been issued. Until
then files are stored as before, and Diagnostics says why.

### 3. Tested automatically where that's safe, by people where it isn't

Every day (and at start-up) CaseBook checks that every envelope copy is present, names the current key and opens
with the server's protection, that each recovery copy matches its configured certificate, and that a CyberArk key
still matches. A failure alerts the integrity distribution once and shows on Diagnostics.

The offline backups can't be tested unattended: a server able to open them alone would hand that ability to anyone
who took over the server. So `casebook-keytool check-share` validates a share on any machine in seconds, and
`casebook-keytool verify` is the full drill with a recovery certificate or the shares. The drill date is recorded,
and Diagnostics reminds after 12 months.

### 4. A missing key pauses evidence, not CaseBook

If the key can't be opened, CaseBook still starts and cases, timelines, tasks and notes work. Evidence and report
downloads, uploads and report generation answer 503 ("the evidence key isn't available; an administrator has been
alerted"). New files are refused, never stored in the clear. The evidence re-check reports one "key unavailable"
finding, with one alarm: a Critical log line, the integrity email and the administrators' banner. The key is
checked again every 5 minutes, so a restored certificate clears it without a restart.

CaseBook never makes a new key while an envelope or a stored file names a key it can't open, or while the
database can't be read. That's the one hard stop: a new key there would leave the old files unreadable forever.

### 5. The file format, CBE1

A header (format version, key id, a random file id, the file key encrypted under the evidence key), then 64 KiB
chunks sealed with AES-256-GCM. Each chunk's nonce is its index under the file's own key. Its authenticated data is
the file id, the index and whether it's the last chunk, so cutting, reordering or swapping chunks between files all
fail. Reads can seek, so thumbnails and the safe zip stream.

The recorded SHA-256 and size stay those of the original file. The re-check, custody, reports and the compliance
bundle keep their meaning, and an examiner compares against the original. No hash of the encrypted file is stored:
GCM already detects any change to it.

Files stored before encryption are converted in the background (15 minutes after start-up, or at once with
**Convert now**). Each file is checked against its recorded hash, encrypted to a temporary copy, decrypted and
checked again, and only then moved over the original. A file that doesn't match is left as it is and reported. The
reader handles both plain and CBE1 files.

## Alternatives considered

- **BitLocker or storage encryption only.** It protects a stolen disk, but not a backup copied off the volume, and
  antivirus on the running server still sees every sample. Recommended alongside, not instead.
- **SQL Server TDE or storing files in the database.** It covers the database only; evidence stays on disk.
- **A new certificate or vault object just for evidence.** More to manage and back up, for no gain over the
  integrity keys every production site already has. It's still possible (item 1 in section 1) for a site that wants
  it.
- **Rotating the evidence key.** Every file header would be rewritten, and every share and recovery copy issued
  would stop working. A compromised key means the server was compromised, when the files were readable anyway.
  Certificate changes, the real lifecycle event, re-encrypt only the envelope. A one-off re-encryption tool can be
  written if it's ever needed.
- **Storing a hash of each encrypted file.** It's redundant with GCM's tags, and one more value to keep in step.
- **Stopping CaseBook when the key is missing.** Safer-looking, but it takes the whole incident record offline over
  a storage problem. Pausing evidence alone keeps responders working.

## Consequences

- Antivirus on the server no longer sees samples once they're encrypted, so no exclusion is needed. Files stored
  before stay visible to it until they're converted.
- Conversion is one-way: earlier CaseBook versions can't read CBE1 files. A rollback after conversion also needs the
  evidence store restored from before it, or the files exported with `casebook-keytool export`.
- The database, the evidence store and the keys folder must be restored as a set, then checked with
  `casebook-keytool verify` before serving.
- Decryption adds about half a second of CPU per 2 GB re-checked (3.9 GB/s on one core), less than the SHA-256 the
  re-check already computes, so the disk or the share remains the limit
  ([integrity.md](../architecture/integrity.md#evidence-encryption-at-rest)).
- Recovering from a lost server certificate is a documented procedure with the keytool, and needs a custodian:
  that's the price of backups the server can't open alone.
