# The public keys CaseBook's release bundles are signed with. Upgrade-CaseBook.ps1 and Test-CaseBookBundle.ps1 trust a
# bundle whose casebook-<v>.zip.sig verifies against one of these (RSA-PSS, SHA-256), and, while any is pinned, refuse
# one with no signature unless -AllowUnsigned is passed. With none pinned they check the SHA-256 only, as before signing.
#
# Each entry: @{ Id = '<first 16 hex characters of the SHA-256 of the key's SubjectPublicKeyInfo>'; Added = '<date>';
#                Xml = '<RSAKeyValue><Modulus>...</Modulus><Exponent>...</Exponent></RSAKeyValue>' }
#
# Don't edit by hand: tools/signing/New-ReleaseSigningKey.ps1 adds a key above the marker line below. It's an array so a
# new key can be added, and shipped in a release signed by the old one, before releases are signed with the new one
# (docs/development/releasing.md, "Rotating the key"). Removing a key stops installs that upgrade past this file from
# trusting it.
#
# Dot-source this file. ASCII only.
$CaseBookReleaseKeys = @(
    # --- New-ReleaseSigningKey.ps1 adds each key above this line ---
)
