# 0019. Releases are signed with a pinned key

- **Status:** Accepted
- **Recorded:** 2026-11-13
- **Accepted:** 2026-11-13. The owner chose signed releases with a pinned public key, and an offline hash check for
  servers that can't reach github.com.

## Context

An upgrade runs the new release's scripts as an administrator on the web server. Until v1.21.0 the only check on a
bundle was its SHA-256 against the release's `.sha256`, fetched from github.com. That has two gaps. Many servers can't
reach github.com, so the check was skipped with a warning, and there was no way to give the hash by hand. And a hash
fetched from the same place as the zip proves only that the two match: whoever can change one can change the other.

## Decision

- **Every release is signed.** The Release workflow signs `casebook-<v>.zip` with the private key in the repository
  secret `RELEASE_SIGNING_KEY`: RSA-3072, RSA-PSS with SHA-256 and a 32-byte salt, by `openssl dgst` on the runner. It
  publishes `casebook-<v>.zip.sig` beside the zip and its `.sha256`. Without the secret the release fails, so no release is
  published unsigned. It also fails when the secret's public key isn't one the repository pins, and it runs
  `Test-CaseBookBundle.ps1` on the signed bundle before publishing, so a wrong secret or mismatched parameters never ship.
- **The trusted keys are pinned in the scripts**, in `deploy/lib/CaseBookReleaseKeys.ps1`: an array of public keys as RSA
  XML (which loads with `FromXmlString` on Windows PowerShell 5.1 and PowerShell 7), each with an id, the first 16 hex
  characters of the SHA-256 of its SubjectPublicKeyInfo. Not a certificate authority, nor Authenticode: CaseBook has one
  publisher, and a pinned key needs no infrastructure, no expiry and no network.
- **The installed script checks the new bundle**, before it expands it or hands over to the bundle's own script,
  because a bundle can't vouch for itself. A signature that doesn't verify is refused. While any key is pinned, a
  bundle with no signature is refused unless `-AllowUnsigned` (bundles from before signing, and downgrades to them),
  which falls back to the hash with a warning. With no key pinned, the hash checks are all there is, as before.
- **The hash can be checked offline.** `-ExpectedSha256 <hex>`, or the release's `.sha256` beside the zip, is used
  before github.com is asked. github.com is asked only for an unsigned bundle with neither.
- **The key is made once by the owner**, with `tools/signing/New-ReleaseSigningKey.ps1`: it sets the secret through
  `gh` (the key is never shown), writes the only other copy to a backup the owner keeps offline, and pins the public
  key. Nothing in CI or the tests uses the real key; the tests make throwaway keys.
- **A new key is rotated in through a release signed by the old one**: pin the new key, release (signed by the old),
  then switch the secret. Installs learn the new key from a release they already trust.
- `Test-CaseBookBundle.ps1` runs the same checks without upgrading, for a workstation before the zip goes to the server
  and for a first install.

## Consequences

- v1.21.0's scripts pin no key, so the first signed release (v1.22.0) is checked by its hash only when installed or
  upgraded to; signatures protect the upgrades after it.
- `Install-CaseBook.ps1` comes inside the bundle and can't check it. A first install is checked by hand: with
  `Test-CaseBookBundle.ps1` from an earlier release's deploy folder, or against the hash on the release page.
- Losing the private key means no further release can be signed with it. A new key then can't be introduced through a
  signed release, so each install takes the next bundle with `-AllowUnsigned` and its hash checked, or has its
  `CaseBookReleaseKeys.ps1` replaced by hand. A leaked key is handled the same way, after removing it from the pinned list.
- An install that skips the release that introduced a new key refuses bundles signed by it, and upgrades through that
  release first.
- Anyone who can write to an install's `<site folder>-deploy` can change the pinned keys; that folder is writable only
  by Administrators and SYSTEM.
