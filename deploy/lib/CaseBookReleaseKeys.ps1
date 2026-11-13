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
    @{ Id = '2a25b163af9a17df'; Added = '2026-11-13'; Xml = '<RSAKeyValue><Modulus>o0MTNdkvnPbWbm8l2hh+MYl2Hp4VMzI044XE5OqCOBktkRKibQb0iBVdVZLaAAaXWioTMBKPDmdLGVrfU7/wEvACuK7zzwnLQ6XGwu6GuZRWr7RSpYFjXrWdgNLQSBQMw8hfP434b1wUcz7Xu99h2lIEeBQOp1pjFJxXBmbrg4IBxsg9ujvgmNN4kxUJMtxtamfJ6QDmuo06dsgEMB1k9CqcxQrZEnYWsdyQas+CRLC6mhn6TKoG2VG42prc5dWSi1joJZ95QQI96D375KzcWmr2X4/Ak+YKbl9VEmYjTZtHMl9bITrvD8f7NIauKxtKgRlkVtC5GQfgy3D+qXqWDnejLyWnWa+kCwdpGHPrSo4obQoJdXwolPv2UpA7c/O+28RB8dVFjKdxNcXKbV3xncXsXeAVs6Cu0rdCMFmA+d6wdE09oJUQvhatd9Lmet5r6pTASbb3gIdJZTU0MDOqdP9RxVTMc3zBHiv6YsHZcwocO8M8I3y4GTq1U5jRgFFp</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>' }
    # --- New-ReleaseSigningKey.ps1 adds each key above this line ---
)
