# Keys and certificates

Section 2 of the [operations guide](../OPERATIONS.md), which keeps the deploy-time checklist and the host controls. Section numbers are kept, so "OPERATIONS.md section 2" in the app and the scripts means this page.

## 2. Integrity Signing-Key Management (F-05b)

Integrity seals are signed with an RSA key (RSA-3072, RSASSA-PSS-SHA256 with a 32-byte salt). Seals and configuration bundles signed before v1.4.0 (RSASSA-PKCS1-v1_5-SHA256) still verify: each is checked by the algorithm it records. **Only in Development**
does the app generate a missing key at `Integrity:SigningKeyPath` (`App_Data/keys/seal-signing.pem`). In any
other environment a missing key **stops startup** ("The seal-signing key … doesn't exist"), because a key the
app made for itself on the server means a host compromise could re-sign forged seals. Install the production
key **before the app first starts**.

### Where the key can live

`Integrity:SigningKey:Source` chooses. It's server configuration only, never an in-app setting.

| Source | What protects the private key | Good for | Watch for |
|---|---|---|---|
| `CertificateStore` (**recommended**) | Windows keeps it in `LocalMachine\My`, encrypted with machine DPAPI, and a **non-exportable** key can be used but never copied off the server | Most installs. Made on the server in one command. | The app-pool account needs read on the private key. |
| `File` (the default) | Only the file's permissions: a PEM at `Integrity:SigningKeyPath`, readable by the app account | Simple installs, or a key you want to move between servers | Anyone who can read the file, or a copy of the disk or a backup, has the key. |
| `CyberArk` | Your vault. The key is fetched once at start-up and held only in memory | Organizations that already keep secrets in CyberArk | Needs `Secrets:CyberArk` (§6). CyberArk's log shows each fetch. |

**Not supported:**
- **A DPAPI-protected key file.** CaseBook doesn't read one. The certificate store already protects its keys with
  DPAPI, and adds non-exportability, so use `CertificateStore` for that.
- **An HSM** works through `CertificateStore` when its vendor supplies a Windows key storage provider (KSP). The
  certificate appears in `LocalMachine\My` while the key stays in the HSM. The KSP must support RSA-PSS signatures
  with SHA-256.
- **Azure Key Vault and other cloud key services** aren't: CaseBook is on-premises and calls no cloud service
  ([ADR 0001](../decisions/0001-blazor-server-on-prem.md)).

**What to back up.** Losing the signing key loses no data. You install a new key, and every earlier seal still
verifies against the old key's **public** half. So:
- Keep the public half of every key you use (`casebook-keytool signing-public-key`, below), with its key id, in your
  key inventory and in the retired keys folder when you replace it.
- A non-exportable certificate-store key can't be backed up, and doesn't need to be.
- A `File` key is in the keys folder backup (§1). Protect that backup accordingly.
- A `CyberArk` key is covered by your vault's backup.

Whichever the source, a key that can't be loaded stops startup with a message naming the setting. The Integrity page
shows the source and the key id in force.

#### Tools

`casebook-keytool` (in `deploy\keytool`) does what Windows PowerShell 5.1 can't: it writes and reads PEM keys.

| Command | Does |
|---|---|
| `new-signing-key --out <file.pem>` | Makes an RSA-3072 key as a PEM file readable only by you, writes its public half beside it (`<name>.public.pem`), and prints the key id. |
| `signing-key-pfx --pem <file.pem> --out <file.pfx>` | Puts an existing PEM key into a password-protected PFX for the certificate store. Same key, same key id. |
| `signing-public-key --site <site folder> [--out <file>]` | Writes the public half of the key the site uses (also `--pem <file>`, or `--cert <thumbprint>`). |
| `rotate-signing-key --site <site folder> (--pfx-out <file.pfx> \| --pem-out <file.pem>)` | Rotation's first two steps in one: saves the current key's public half into the retired keys folder and makes the new key, then says what to change (*Rotating the signing key*). |
| `enable-chain-key --site <site folder> --cert <thumbprint> [--backup-done]` | Turns the audit chain key on with a certificate, once its backup is confirmed (*The audit chain key*). |
| `retire-custodian --site <site folder> --cert <thumbprint> [--note "<text>"]` | Takes a recovery certificate out of the evidence key's settings and envelope, recorded in the audit trail (*Retiring a custodian*). |

Each step below shows the keytool command first. Where PowerShell can do the same, that's shown too, with OpenSSL as
the alternative.

### Setting up the key

The app never makes a production key itself: outside Development, a missing key stops startup. Do one of these
before the site's first start (the installer's answers file sets the same settings: INSTALL.md §4).

#### A. In the certificate store (recommended)

On the server, in an elevated Windows PowerShell:

```powershell
$s = New-SelfSignedCertificate -Subject "CN=CaseBook seal signing" -CertStoreLocation Cert:\LocalMachine\My `
     -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy NonExportable -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(25)
$s.Thumbprint
```

1. Let the app account read the private key. In `certlm.msc`, go to *Personal › Certificates*, right-click the
   certificate, choose *All Tasks › Manage Private Keys*, and add `IIS APPPOOL\CaseBook` (your app pool's name) with
   **Read**.
2. In `appsettings.Production.json`:

   ```json
   "Integrity": {
     "SigningKey": { "Source": "CertificateStore", "CertificateThumbprint": "<thumbprint>", "StoreLocation": "LocalMachine" }
   }
   ```

3. Recycle the app pool. The Integrity page shows the key id.
4. Keep the public half (see [Saving the public half](#saving-the-public-half)).

Self-signed is fine: trust comes from the key id you record, not from a chain, and nothing checks the dates. Any RSA
certificate of 2048 bits or more works, including one from your CA or an HSM.

#### B. As a PEM file

On an admin workstation, not the server:

```powershell
deploy\keytool\casebook-keytool new-signing-key --out .\seal-signing.pem
```

PowerShell 7 can make one too (not Windows PowerShell 5.1, which can't write PEM). Then restrict the file yourself:

```powershell
$rsa = [System.Security.Cryptography.RSA]::Create(3072)
Set-Content -Path .\seal-signing.pem -Value $rsa.ExportPkcs8PrivateKeyPem() -NoNewline
```

Or with OpenSSL: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out seal-signing.pem`.

1. Copy it to the server's keys folder, for example `E:\CaseBookData\keys\seal-signing.pem`, and lock it down:

   ```powershell
   icacls E:\CaseBookData\keys\seal-signing.pem /inheritance:r /grant:r "IIS APPPOOL\CaseBook:R" "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F"
   ```

2. Set `Integrity:SigningKeyPath` to it (the installer sets `<DataRoot>\keys\seal-signing.pem`), and leave
   `Integrity:SigningKey:Source` as `File`.
3. Recycle the app pool, check the key id on the Integrity page, and delete the workstation's copy (keep the
   `.public.pem`).

#### C. In CyberArk

1. Make a PEM key as in B, on an admin workstation.
2. Store the file's whole content (from `-----BEGIN PRIVATE KEY-----` to the end line) as a CyberArk object.
3. Set:

   ```json
   "Integrity": { "SigningKey": { "Source": "CyberArk", "Secret": "@cyberark:Safe=<safe>;Object=<object>" } }
   ```

   and turn on `Secrets:CyberArk` (§6).
4. Recycle the app pool, check the key id, and delete the local PEM (keep the `.public.pem`).

#### Saving the public half

Do this for every key, now and before you replace it:

```powershell
deploy\keytool\casebook-keytool signing-public-key --site C:\inetpub\casebook --out .\<key id>.pem
```

For a key in the certificate store, Windows PowerShell 5.1 can do it alone:

```powershell
$c = Get-Item Cert:\LocalMachine\My\<thumbprint>
"-----BEGIN RSA PUBLIC KEY-----`r`n" + [Convert]::ToBase64String($c.PublicKey.EncodedKeyValue.RawData, 'InsertLineBreaks') +
  "`r`n-----END RSA PUBLIC KEY-----" | Set-Content .\signing-public.pem -Encoding Ascii
```

With OpenSSL, for a PEM file: `openssl pkey -in seal-signing.pem -pubout -out seal-signing.public.pem`. A
compliance bundle also carries it as `signing-public-key.pem`.

### Moving between sources

```mermaid
flowchart TD
    from{"Where is the key now?"}
    from -->|"File or CyberArk:<br/>you hold the PEM"| same["Move the same key.<br/>The key id stays, nothing else changes."]
    from -->|"Certificate store,<br/>non-exportable"| rotate["The key can't leave the store:<br/>make a new key and retire the old one"]
    same --> s1["To the certificate store:<br/>signing-key-pfx, then Import-PfxCertificate"]
    same --> s2["Between File and CyberArk:<br/>copy the PEM's content"]
    rotate --> r1["Save the old public half<br/>into the retired keys folder"]
    r1 --> r2["Set up the new key: A, B or C"]
```

**The same key, from a file (or CyberArk) into the certificate store:**

Run these in PowerShell opened with **Run as administrator**: the key file on the server is readable only by SYSTEM,
Administrators and the app-pool account, and an administrator's ordinary window doesn't count as Administrators. If
it still can't be read, the file names one account only (`icacls <file>` shows who); take it over and let
administrators read it, which leaves the app's access as it is:

```powershell
takeown /f E:\CaseBookData\keys\seal-signing.pem /a
icacls E:\CaseBookData\keys\seal-signing.pem /grant "BUILTIN\Administrators:R"
```

1. On an admin workstation, or the server: `casebook-keytool signing-key-pfx --pem .\seal-signing.pem --out .\seal.pfx`
   (it asks for a password). With OpenSSL:

   ```powershell
   openssl req -new -x509 -key seal-signing.pem -subj "/CN=CaseBook seal signing" -days 9125 -out seal.crt
   openssl pkcs12 -export -inkey seal-signing.pem -in seal.crt -out seal.pfx
   ```

2. On the server, import it. It isn't exportable unless you add `-Exportable`, which you shouldn't:

   ```powershell
   Import-PfxCertificate -FilePath .\seal.pfx -CertStoreLocation Cert:\LocalMachine\My -Password (Read-Host -AsSecureString "PFX password")
   ```

   An OpenSSL 3 PFX needs Windows Server 2019 or later; for Server 2016, add `-legacy` to the `pkcs12` command.
3. Grant the app account read on its private key, and set `Integrity:SigningKey` as in A with the new thumbprint.
4. Recycle the app pool. The key id on the Integrity page is the same as before.
5. Delete the PFX, and the PEM file from the server and the workstation. A copy left behind keeps the old weakness.
   Old backups of the keys folder still hold it.

**The same key, between File and CyberArk:** put the PEM's content into the vault object (or the vault's content into
the file), change `Source`, recycle. The key id stays.

**From the certificate store to anywhere else:** a non-exportable key can't be moved, so this is a rotation (below):
save its public half first, then set up the new key.

> **Before switching away from a certificate, leave it in the store.** If `Storage:Encryption:CertificateThumbprint`
> is blank, the evidence key is locked to the signing certificate (§2, Evidence key). With the old certificate still
> in the store, a new signing certificate takes over the lock at the next check. With no certificate at all (moving
> to `File` or `CyberArk`), set `Storage:Encryption:CertificateThumbprint` to the old certificate's thumbprint first,
> or evidence stops opening. A `@protected:` value (the SMTP password) made with the signing certificate also needs
> that certificate to stay. Delete the old certificate only once Diagnostics shows the evidence key **On** and the SMTP sign-in working.

### The audit chain key (F-25, off by default)

Without it, each audit entry's hash is plain SHA-256, so someone who can write to the database can rewrite the
entries made since the last seal (6 hours by default) and recompute every hash after them. With the chain key on,
new entries are hashed with HMAC-SHA256 under a secret the database doesn't hold, so that no longer works. Entries
written before keep their plain hash and still verify; the first keyed entry marks the switch, and every entry after
it must be keyed.

**Turning it on with a certificate**, in three steps:

1. Make or choose the certificate (the signing certificate can serve), in `LocalMachine\My`, with the app-pool account
   given read on its private key. **Back it up with its private key** to a password-protected PFX kept offline.
2. On the server, as an administrator:

   ```powershell
   deploy\keytool\casebook-keytool enable-chain-key --site C:\inetpub\casebook --cert <thumbprint>
   ```

   It checks the certificate's private key works and that the key file won't land in the site folder, then stops and
   reminds you of the backup. Run it again with `--backup-done` and it writes `Integrity:ChainKey` (`Enabled`,
   `Source: Certificate`, the thumbprint), keeping the old settings file beside it.
3. Restart the app pool. CaseBook makes the key and keeps it in `chain-key.json`, encrypted to the certificate: back
   that file up too. The Integrity page shows the chain key's id.

With CyberArk, set the settings below by hand.

`Integrity:ChainKey` (server configuration only):

| Setting | Meaning |
|---|---|
| `Enabled` | `false` by default. |
| `Source` | `CyberArk` or `Certificate`. |
| `Secret` | CyberArk: an `@cyberark:Safe=…;Object=…` reference to **32 random bytes, base64-encoded**. |
| `RetiredSecrets` | CyberArk: references to earlier keys, so entries hashed with them still verify. |
| `CertificateThumbprint`, `StoreLocation` | Certificate: the certificate the key is encrypted to (it can be the signing certificate); the app account needs read on its private key. |
| `WrappedKeyPath`, `RetiredWrappedKeysPath` | Certificate: the encrypted key file and a folder of earlier ones. The installer sets them to `<DataRoot>\keys\chain-key.json` and `<DataRoot>\keys\chain-retired`; blank means `chain-key.json` and `chain-retired` beside `SigningKeyPath`, even when the signing key isn't a file. Keep them out of the site folder: an upgrade mirrors it from the new build. If they're blank and that folder is in the site (no `SigningKeyPath`), `Upgrade-CaseBook.ps1` copies any files there to `<DataRoot>\keys` and sets the paths (and `RetiredPublicKeysPath`), and stops instead if a different file is already there. |

Making a CyberArk key (Windows PowerShell or PowerShell 7), then storing the output as the object's content:

```powershell
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)
```

With `Certificate`, CaseBook makes the key on its first start with the chain key on, and keeps only its encrypted
form in `chain-key.json` (which names the certificate). The file is useless without the certificate's private key.

**Before turning it on, back the key up.** Turning it on is one-way in practice: keyed entries can only be checked
while their key is held. If the key is lost, the integrity check reports the first keyed entry as unverifiable
("hashed with chain key …, which this server doesn't hold") and keeps alarming; the seals still prove the history
up to each seal is intact, but the per-entry check can't run. So: for CyberArk, make sure the object is in your
vault backup; for Certificate, back up the certificate with its private key **and** `chain-key.json`. Don't turn the
chain key off afterwards: new entries would get the plain hash, and the check reports that as a break.

A key that can't be loaded stops startup with a message naming the setting. So does a missing `chain-key.json` on a server whose audit log already has entries keyed with a key it doesn't hold (a restore without the keys folder, a moved `WrappedKeyPath`): restore the file rather than letting CaseBook start a new key that would leave those entries unverifiable. So does a missing `chain-key.json` while the database can't be read (unreachable, offline, restoring, or the app account refused): CaseBook can't tell a first start then, so it waits until the database is back. A rotation, with the old file in `chain-retired`, starts normally. The Integrity page shows whether the
chain key is on, where it comes from and its key id (key ids are derived from the key and reveal nothing).

**Rotating it:** CyberArk: put the old reference in `RetiredSecrets`, point `Secret` at a new object, restart.
Certificate: move `chain-key.json` into `chain-retired`, restart (a new key is made; the old file still decrypts,
even if it was encrypted to an earlier certificate that's still in the store).

### Extra seal copies (F-27, each off unless set)

Every seal is already written to the database, to `Integrity:ExportPath` and, with a SIEM transport on, to the SIEM
as event 5004 (§5). The copy that matters is one the people who run CaseBook's database and servers can't change.
Three optional extras:

- **An append-only share.** Point `Integrity:ExportPath` at a share on a server CaseBook's administrators don't
  administer, and let the app account create files there but not change or delete them. On the share's folder,
  give the account the right to create files in the folder itself, and only read on the files it holds:

  ```powershell
  icacls '\\files01\casebook-seals' /grant 'CONTOSO\svc-casebook$:(WD,AD,RA,REA,RC,X)'
  icacls '\\files01\casebook-seals' /grant 'CONTOSO\svc-casebook$:(OI)(IO)(R)'
  ```

  CaseBook writes each seal file in the same call that creates it, so it never needs to reopen one for writing.
  Confirm on your file server that the account can create a file there but not replace or delete one, and that the
  share permissions don't grant more. It isn't WORM: an administrator of that file server can still change files,
  so keep that role apart from CaseBook's.
- **A seal digest by email** (`Integrity:SealCopies:EmailTo`, comma-separated): each seal's sequence, chain-head
  hash, key id, time and signature, to a mailbox under Microsoft 365 retention or a litigation hold. Needs email
  turned on in-app; with email off, the copy is reported as failed rather than skipped.
- **RFC 3161 timestamps** (`Integrity:SealCopies:TimestampAuthorityUrl`): for an organization with its own timestamp
  authority. Only internal addresses are accepted (the host must resolve to private, loopback or link-local
  addresses; anything else stops startup), so CaseBook never sends seals to the internet. Each token is saved beside
  the seal's JSON copy as `seal-<sequence>-<time>-<id>.tsr` (each seal its own file); check one with
  `openssl ts -verify -data payload.txt -in seal-….tsr -token_in -CAfile <your TSA's CA>` (the payload as in
  `VERIFY.txt`). A timestamp proves the seal existed at that time, so even someone holding the signing key can't
  backdate a rewritten history.

A failed copy never undoes the seal: it's logged, sent as SIEM event 5005 naming the destination, and shown under
**Integrity & audit → Keys and seal copies** with its last error.

### Rotating the signing key

Rotate on a set schedule, and at once if the key may have been exposed. Diagnostics reminds you (*Signing key
rotation*, also under *Needs attention*) once the key has signed seals for `Integrity:RotationReminderDays` (default 365;
0 turns it off), counted from its first seal. Old seals stay valid: each records the key id
and algorithm that signed it, and is checked with that key.

**In one command**, on the server as an administrator (steps 1 and 2 below; step 3 is still yours):

```powershell
deploy\keytool\casebook-keytool rotate-signing-key --site C:\inetpub\casebook --pfx-out E:\Temp\seal-signing-new.pfx
```

It saves the current key's public half into the retired keys folder, makes the new key (in a PFX, asking for its
password; or `--pem-out` for a PEM file) and prints the import command and the settings to change. It changes no
settings: install the new key, change them, recycle. A key in CyberArk can't be read by the tool: save its public half
by hand (step 1). By hand:

1. **Save the current key's public half into the retired keys folder.** That's `Integrity:RetiredPublicKeysPath`, or a
   `retired` folder beside the signing key when that's blank:

   ```powershell
   deploy\keytool\casebook-keytool signing-public-key --site C:\inetpub\casebook --out E:\CaseBookData\keys\retired\<key id>.pem
   ```

   (or the PowerShell or OpenSSL commands in [Saving the public half](#saving-the-public-half)). Every `*.pem` there
   is read at startup. A private-key file works too (only its public half is kept), but keep private keys out of
   that folder. A file that isn't a readable RSA key stops startup, naming the file.
2. **Set up the new key**, by A, B or C above, and change the settings to point at it. Recycle the app pool.
3. **Check:** the Integrity page shows the new key id; re-verify an older seal, and it reports authentic. A seal
   whose key isn't held says so ("Signed by key …, which this server doesn't hold"): add that key's public half to
   the folder.

**A lost key** (the server or the certificate is gone) is the same, starting from the public half in your key
inventory or a compliance bundle.

Compliance bundles include every retired public key (`retired-public-keys/<KeyId>.pem`), so an examiner can check
seals from before the rotation offline. Public keys aren't secret, but the folder must be protected from change, like
the rest of the data root.

### Renewing certificates

**Administration › Diagnostics** lists every certificate the configuration names, and flags one 60 days before it expires,
once it has, or when it isn't in the store (also under *Needs attention*). The TLS certificate is found by its name
matching `App:BaseUrl`'s host, since the app can't read IIS's binding: Diagnostics says *probably*. Recovery
certificates are watched with the evidence key.

CaseBook doesn't check the dates on the certificates that hold its keys: an expired one goes on signing and opening.
Renew them for your policy, and before the old one is removed. The TLS and client certificates are another matter:
the other end refuses an expired one.

| Certificate | What expiry breaks | Renewing it |
|---|---|---|
| Seal signing key (`Integrity:SigningKey`) | Nothing in CaseBook | A new certificate is a new key: rotate (*Rotating the signing key*, above), so old seals still verify |
| Audit chain key (`Integrity:ChainKey`, Certificate) | Nothing in CaseBook | Set `CertificateThumbprint` to the new one, move `chain-key.json` into `chain-retired`, restart. Keep the old certificate in the store: the retired file still needs it |
| Evidence key server lock (`Storage:Encryption`) | Nothing in CaseBook | Leave the old one in the store; the key moves to the renewed one at the next check (*Evidence key*, *What else to know*, below) |
| `@protected:` values (§6) | Nothing in CaseBook | Make each value again for the new certificate (`casebook-keytool protect-secret`) before removing the old one |
| TLS (the IIS binding) | Browsers refuse the site | Renew it and change the site's HTTPS binding in IIS; then set `App:BaseUrl` if the host name changed |
| CyberArk client (`Secrets:CyberArk:ClientCertificateThumbprint`) | CyberArk refuses CaseBook, so secrets from it stop resolving | Install the new one, grant the app-pool account read on its private key, set the thumbprint, recycle |
| Syslog client (`Siem:Syslog:ClientCertificateThumbprint`) | The syslog server may refuse the connection | As for the CyberArk client certificate |

### Evidence key: encryption at rest, backups and recovery (PROD-57)

With this on, evidence files and generated reports are stored encrypted (AES-256-GCM), so a copied disk or backup
doesn't expose them and the server's antivirus can't delete a malware sample. Why it's built this way:
[ADR 0017](../decisions/0017-evidence-encryption-and-key-recovery.md). Off by default.

**Losing the key loses every encrypted file.** Set up the backups below before turning it on, and run a drill.

#### How it works

You don't make the evidence key. CaseBook makes it (a random 256-bit key) the first time it starts with encryption
on, and never stores it in the clear. It stores **locked copies** of it instead, in a small file called the
*envelope*. Each certificate you give it locks one copy with its public key; only the matching private key unlocks
that copy.

| Lock | What it is | Where its private key lives | When it's used |
|---|---|---|---|
| **Server lock** (one) | A certificate on the CaseBook server, in `LocalMachine\My`. It can be one you already have for the audit trail (step 1). | On the server, non-exportable, readable by the app-pool account | Every time CaseBook starts, to open the key |
| **Recovery locks** (one per recovery certificate; make two) | Certificates made on another machine. The server is given only their public part (`.cer`). | Offline: in a safe or on a smartcard, with a custodian | Only in a disaster, by `casebook-keytool`, to get the key back |
| **Shares** (optional, instead of or as well as recovery certificates) | The key cut into 5 pieces, any 3 of which rebuild it | On paper or USB, with 5 different people | Only in a disaster |

So the **recovery certificate is not the server's certificate**, and its private key is never on the server. The
server lock is what CaseBook uses day to day, and it's lost with the server (a rebuild, a deleted certificate, a
ransomware wipe). The recovery locks are the way back when that happens. Because their private keys aren't on the
server, someone who takes over the server can't use them.

**Why two recovery certificates?** Any one of them recovers the key. With two, one lost `.pfx`, forgotten password or
departed custodian doesn't lose everything. Keep them with different people, in different places.

```mermaid
flowchart LR
    K["Evidence key<br/>made by CaseBook,<br/>never stored in the clear"]
    K -->|locked to| S["Server certificate<br/>on the server"]
    K -->|locked to| A["Recovery certificate A<br/>private key offline, custodian A"]
    K -->|locked to| B["Recovery certificate B<br/>private key offline, custodian B"]
    K -.->|optional| SH["Shares: any 3 of 5"]
    S --> D["Daily use:<br/>CaseBook opens the key at start-up"]
    A --> R["Disaster:<br/>casebook-keytool recover or export"]
    B --> R
    SH -.-> R
```

#### Choosing your setup

```mermaid
flowchart TD
    start([Turn on evidence encryption]) --> q1{"Is the audit chain key on with a certificate or CyberArk,<br/>or the signing key in the certificate store?"}
    q1 -->|"No: the default install,<br/>signing key is a PEM file"| make["Step 1: make a server certificate"]
    q1 -->|Yes| q2{"Use that certificate or key,<br/>or keep the evidence key apart?"}
    q2 -->|Use it| none["Step 1: nothing to do"]
    q2 -->|Keep it apart| make
    make --> rec["Step 2: make two recovery certificates<br/>on another machine"]
    none --> rec
    rec --> on["Step 3: turn it on"]
    on --> q3{"Also want shares?<br/>No single person can recover alone"}
    q3 -->|Yes| split["Step 4: issue shares"]
    q3 -->|No| drill["Step 5: check Diagnostics shows On,<br/>then run a drill"]
    split --> drill
```

You need a server lock and at least one backup (a recovery certificate or shares). Until both exist, nothing is
encrypted: evidence is stored as before and Diagnostics says what's missing.

#### Step 1: the server lock

CaseBook uses the first of these that's set:

1. `Storage:Encryption:CertificateThumbprint`: a certificate of its own, kept apart from the audit trail's.
2. The audit chain key's certificate (`Integrity:ChainKey`, `Enabled` true, `Source` `Certificate`).
3. The seal-signing certificate (`Integrity:SigningKey:Source` `CertificateStore`).
4. A key derived from the chain key in CyberArk (`Integrity:ChainKey:Source` `CyberArk`).

**If none is set** (the default install, whose signing key is a PEM file), make a certificate on the server, in an
elevated PowerShell:

```powershell
$s = New-SelfSignedCertificate -Subject "CN=CaseBook evidence key" -CertStoreLocation Cert:\LocalMachine\My `
     -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy NonExportable -KeyUsage KeyEncipherment -NotAfter (Get-Date).AddYears(10)
$s.Thumbprint
```

Then let the app-pool account read its private key. In `certlm.msc`, go to *Personal › Certificates*, right-click the
certificate, choose *All Tasks › Manage Private Keys*, and add `IIS APPPOOL\CaseBook` (your app pool's name) with
**Read**. Put the thumbprint in `Storage:Encryption:CertificateThumbprint` (step 3).

- Self-signed is fine: nothing checks its chain.
- Non-exportable means it can be used on this server but never copied off it. That's deliberate: the recovery
  certificates are the copy.
- At install, setting `EvidenceKeyThumbprint` in the answers file grants the read for you.

#### Step 2: two recovery certificates

On a machine **other than the CaseBook server** (an admin workstation), once per custodian, changing the letter:

```powershell
$c = New-SelfSignedCertificate -Subject "CN=CaseBook evidence recovery (custodian A)" -CertStoreLocation Cert:\CurrentUser\My `
     -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy Exportable -KeyUsage KeyEncipherment -NotAfter (Get-Date).AddYears(10)
Export-Certificate -Cert $c -FilePath .\casebook-recovery-a.cer
Export-PfxCertificate -Cert $c -FilePath .\casebook-recovery-a.pfx -Password (Read-Host -AsSecureString "PFX password")
Remove-Item "Cert:\CurrentUser\My\$($c.Thumbprint)" -DeleteKey
```

That leaves two files per custodian:

- `casebook-recovery-a.cer` is the **public** part. Copy it to the server, for example to `<DataRoot>\keys\recovery\`.
- `casebook-recovery-a.pfx` and its password are the **private** part. They go in the custodian's safe (or onto a
  smartcard), never onto the server. The last line removes the certificate from the workstation.

Your certificate authority can issue them instead (RSA, with key-encipherment usage). Expiry doesn't stop recovery;
Diagnostics warns 60 days ahead.

**Give each custodian a copy of the envelope too, after step 3.** A recovery certificate opens the copy of the key
locked to it, and that copy is in the envelope, so recovering with a `.pfx` needs an envelope as well. CaseBook keeps
three (below), and the evidence store's backups carry one; an offline copy covers losing all of them while the
encrypted files survive (say, an evidence backup that skipped the hidden `.key` folder, with the server and database
gone too).

- Once Diagnostics shows **On**, copy `evidence-key.json` from the keys folder (`<DataRoot>\keys`, or `EnvelopePath`) to each custodian, to keep with their `.pfx`.
  It's useless without a private key, so it needs no more protection than the `.pfx` already has.
- Take a fresh copy whenever you add a recovery certificate: a copy only holds locks for the certificates configured
  when it was taken.
- To use it, put it back in the keys folder as `evidence-key.json` (where `casebook-keytool` looks), then `recover` or
  `export` as usual.
- Shares don't need it: they rebuild the key directly.

**Retiring a custodian.** On the server, as an administrator:

```powershell
deploy\keytool\casebook-keytool retire-custodian --site C:\inetpub\casebook --cert <their thumbprint> --note "pfx and envelope copy collected and destroyed"
```

It removes their `.cer` from `RecoveryCertificates` and their lock from the live envelope, keeping the old settings
file beside it, and records it with your note: CaseBook writes it to the audit trail and the SIEM (5007,
`CustodianRetired`). It's refused when theirs is the key's only backup: add another recovery certificate first. Restart
the app pool afterwards. Older envelope copies (and backups taken before) still open with their `.pfx`, since CaseBook
can't change the evidence key itself, so collect their `.pfx` and envelope copy and destroy them.

#### Step 3: turn it on

In `appsettings.Production.json` (the upgrade adds this section, turned off, if it's missing):

```json
"Storage": {
  "Encryption": {
    "Enabled": true,
    "CertificateThumbprint": "<the thumbprint from step 1, or blank to use the integrity certificate>",
    "StoreLocation": "LocalMachine",
    "RecoveryCertificates": [
      "E:\\CaseBookData\\keys\\recovery\\casebook-recovery-a.cer",
      "E:\\CaseBookData\\keys\\recovery\\casebook-recovery-b.cer"
    ]
  }
}
```

Recycle the app pool. CaseBook makes the key and locks it to the server certificate and to each recovery certificate,
and Diagnostics shows **On**. At install, the answers file's `EvidenceEncryption`, `RecoveryCertificates` and
`EvidenceKeyThumbprint` do the same (INSTALL.md §4).

New files are encrypted from then on. Files stored before are converted in the background, starting 15 minutes after
start-up (after `Upgrade-CaseBook.ps1`'s warm-up), or straight away with **Convert now** on Diagnostics. Each is checked
against its recorded hash before and after, and only then replaces the original; one that doesn't match is left as it
is and reported. Conversion needs free space for the largest file. **It's one-way:** an earlier CaseBook version can't
read converted files, so a rollback after it also needs the evidence store restored from before it (or the files
exported, below).

| Setting | Meaning |
|---|---|
| `Enabled` | `false` by default. |
| `RecoveryCertificates` | Paths to `.cer` files (public part only). A `.cer` added or removed later is added to or dropped from the envelope at the next check. |
| `CertificateThumbprint`, `StoreLocation` | Optional: the server lock's own certificate (step 1). Blank uses the integrity keys already configured. |
| `EnvelopePath` | Optional: where the envelope is kept. Blank is `evidence-key.json` beside the seal-signing key (`<DataRoot>\keys`). |

#### Step 4 (optional): shares

Shares need the key to exist, so issue them after step 3. On the server, as an administrator:
`deploy\keytool\casebook-keytool split --site <site folder> [--threshold 3] [--shares 5] [--out <folder>]`.

- Give each share (one line, `CBS1-…`) to a different person or safe, on paper or USB, then delete the output folder
  (`--out` makes it readable by administrators only).
- Any 3 rebuild the key; 2 reveal nothing.
- CaseBook records that shares were issued, never the shares themselves.
- A holder can check theirs, on any machine, with `casebook-keytool check-share`.
- With shares and no recovery certificate, encryption starts once the shares are issued.

#### Step 5: check, and drill

Diagnostics shows the state, the server lock, the envelope copies, the recovery certificates, the shares and the last
drill. The server can't test the offline backups by itself (that would let anyone who took over the server open them),
so drill each one at least once a year; Diagnostics reminds you after 12 months. The custodian brings the `.pfx` to the
server for the drill:

```powershell
casebook-keytool verify --site C:\inetpub\casebook --pfx E:\casebook-recovery-a.pfx   # asks for the password
casebook-keytool verify --site C:\inetpub\casebook --shares                           # asks for the shares
```

#### What else to know

**Certificate renewal.** When the server certificate is renewed and the old one is still in the store, the key is
locked to the new one at the next check (daily, and at start-up). Leave the old certificate in the store until
Diagnostics shows the new one.

**The envelope** is kept in three places: the keys folder, the database (`KeyEnvelopes`) and beside the evidence
(`<store>\.key\evidence-key.json`). A missing or damaged copy is rewritten from a good one at the next check. Back
them up with everything else (section 1). Without a certificate or the shares, they're useless. When the server lock
is the chain key in CyberArk, CyberArk's own vault backup covers it.

**Checks.** Every day CaseBook checks each envelope copy, the recovery copies and the server lock, and alerts the
integrity distribution once per problem.

**When the key can't be opened** (a certificate removed or its rights changed, CyberArk down, a restore without the
keys folder): CaseBook keeps running. Evidence and report downloads, uploads and report generation answer that the
evidence key isn't available, and nothing is stored unencrypted. One alarm goes out (a Critical log line, the
integrity email, the administrators' banner) and Diagnostics names the cause. The key is retried every 5 minutes,
so fixing the cause clears it without a restart. CaseBook never makes a new key while files or an envelope need one
it can't open.

**Recovering the key onto a new certificate** (the server certificate is lost, or a new server):

1. Install the new certificate (with its private key, not exportable) in `LocalMachine\My` on the server, and give
   the app-pool account read on its private key.
2. As an administrator: `casebook-keytool recover --site <site folder> --pfx <recovery .pfx>` (or `--cert
   <thumbprint>` for one on a smartcard, or `--shares`) `--to-cert <new thumbprint>`. The new certificate's private key
   must be usable there, or nothing is changed. Add `--chain-key` to rebuild `chain-key.json` onto the same certificate
   when the chain key was lost with it. It's refused if `chain-key.json` still opens on that server, or if the backup
   carries a chain key the audit log has since stopped using (a rotation after the backup was made); an existing file
   that doesn't open is kept beside the new one as `chain-key.json.replaced-<time>`.
3. Set `Storage:Encryption:CertificateThumbprint` (or the chain key's or signing certificate's, whichever protected
   it) to the new thumbprint, and restart the app pool. Diagnostics shows **On**; run a drill.

**Getting the files out.** `casebook-keytool export --site <site folder> (--case <number> | --all) --out <folder>`
writes each file under its original name, per case, with `manifest.csv` listing each file's recorded and actual
SHA-256 (exit code 2 if any differ). It's for eDiscovery, moving to another product or a disaster. It opens the key
with the server's certificate by default, or `--pfx`, `--cert` or `--shares`. The exported files are live: export
malware only to a quarantined location.

**What the keytool does is recorded.** The tool runs apart from the app and can't write the audit trail, so `split`,
`verify`, `recover` and `export` each leave a record in the keys folder's `evidence-key.json`. Within a minute (while
CaseBook runs; otherwise at its next start) CaseBook writes each to the audit trail (an export as an Export entry with
the case, file count, folder and the manifest's SHA-256) and sends it to the SIEM (5007, or 5307 for an export). Run
the tool on the server, against the site's own keys folder, or the record waits for the envelope to be copied back.
