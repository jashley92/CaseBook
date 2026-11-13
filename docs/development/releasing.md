# Releasing and the signing key

How a release is signed, the key and its secret, and how to set it up, rotate it or recover from losing it. It's for
the owner, who tags releases. What a release contains and how it's built is in
[testing.md](testing.md#continuous-integration); how installs check a bundle is in
[deploy/README.md](../../deploy/README.md#checking-a-bundle); why, in
[ADR 0019](../decisions/0019-releases-are-signed-with-a-pinned-key.md).

**Contents**

- [How a release is signed](#how-a-release-is-signed)
- [Setting up the key](#setting-up-the-key)
- [Rotating the key](#rotating-the-key)
- [A lost or leaked key](#a-lost-or-leaked-key)

## How a release is signed

The `release` job of `.github/workflows/release.yml`, after it zips the bundle and its `.sha256`:

1. **Sign the bundle.** Fails unless the repository secret `RELEASE_SIGNING_KEY` holds a PEM private key. Writes it to
   a `mktemp` file (mode 0600, deleted when the step ends), derives its key id
   (`openssl pkey -pubout -outform DER | sha256sum`, the first 16 hex characters), and fails unless
   `deploy/lib/CaseBookReleaseKeys.ps1` pins that id. Then signs:
   `openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sign <key> -out casebook-<v>.zip.sig casebook-<v>.zip`.
2. **Verify it as an install would.** Runs `deploy/Test-CaseBookBundle.ps1 -Offline` under PowerShell 7 on the runner:
   the signature against the pinned keys and the `.sha256` beside the zip.
3. **Publish** the zip, the `.sha256` and the `.sig` as the release's three assets.

No release is published unsigned: without the secret, or with a secret whose key isn't pinned, the job fails before
anything is published. Fix the secret or merge the pinning, delete the tag and push it again.

## Setting up the key

Once, before the first signed release (v1.22.0). On your workstation, from a clone of the repository, with the GitHub
CLI signed in (`gh auth status`) as an account that can set the repository's secrets:

```powershell
git switch -c release-signing-key origin/main
powershell -NoProfile -ExecutionPolicy Bypass -File toolssigningNew-ReleaseSigningKey.ps1 -BackupPath E:\casebook-release-key.pem
```

`tools/signing/New-ReleaseSigningKey.ps1` runs on PowerShell 7 or Windows PowerShell 5.1. It:

- generates an RSA-3072 key pair;
- writes the private key (PEM, PKCS#8) to `-BackupPath`, which must be a new file. It's the only copy outside
  GitHub's secret store, which can't be read back. Move it offline or into a password manager straight away, and
  delete any other copy;
- pipes the PEM to `gh secret set RELEASE_SIGNING_KEY --repo jashley92/CaseBook`, so it's never on screen or in shell
  history;
- adds the public key to `deploy/lib/CaseBookReleaseKeys.ps1` above the marker line;
- prints the key id and the next steps, and nothing of the key.

Then commit `deploy/lib/CaseBookReleaseKeys.ps1`, open a pull request, merge it, and tag the release as usual. The order
matters: a tag on a commit whose `CaseBookReleaseKeys.ps1` doesn't pin the secret's key fails to release.

`-DryRun -KeysPath <copy of CaseBookReleaseKeys.ps1>` does everything but `gh`, and writes the public key to the copy; the
tests use it with throwaway keys. `-Repository` names another repository's secret.

## Rotating the key

Installs trust only the keys their installed `CaseBookReleaseKeys.ps1` pins, and learn a new one only from a release they
already trust. So a new key goes in through a release signed by the old one:

1. On a branch, run `toolssigningNew-ReleaseSigningKey.ps1 -BackupPath <new file> -Rotate` (PowerShell 7 or Windows PowerShell 5.1). It pins the new key
   beside the old one and leaves the secret alone. Merge the pull request.
2. Tag a release. It's signed by the old key and carries both keys to every install that upgrades to it.
3. Switch the secret to the new key (the script prints this command):
   `Get-Content -Raw <new file> | gh secret set RELEASE_SIGNING_KEY --repo jashley92/CaseBook`
4. Releases from now on are signed by the new key. Once every install has upgraded past step 2, a later release may
   remove the old key from `CaseBookReleaseKeys.ps1`; keep its backup until then.

An install still on a release from before step 2 refuses bundles signed by the new key (the signature is there but
isn't one it trusts). It upgrades to the step 2 release first, then on.

## A lost or leaked key

- **Lost** (no backup, and the secret deleted or overwritten): no release can be signed by a key installs trust.
  Make a new key with the script (without `-Rotate`), merge, and release. Each install takes that release by hand,
  checked by its hash and passed `-AllowUnsigned` after deleting the `.sig` beside the zip, or with its
  `<site folder>-deploy\lib\CaseBookReleaseKeys.ps1` replaced by the new one. Say so in the release notes.
- **Leaked**: anyone with it can sign a bundle installs trust. Replace it as for a lost key, and remove the leaked key
  from `CaseBookReleaseKeys.ps1` in the same pull request. Tell administrators to check bundles against the release page
  until they've upgraded.
