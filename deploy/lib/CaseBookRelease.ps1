# Release integrity for Upgrade-CaseBook.ps1 and Test-CaseBookBundle.ps1: a bundle's signature and its SHA-256, checked
# before anything in it is expanded or run. Nothing here touches IIS or SQL, so it can be tested.
# Dot-source this file.
# ASCII only: Windows PowerShell 5.1 misreads non-ASCII in BOM-less files.

# A release tag, as the Release workflow accepts it: vX.Y.Z.
function Test-CaseBookReleaseTag([string] $Tag) {
    return [bool]($Tag -match '^v\d{1,4}\.\d{1,4}\.\d{1,4}$')
}

# The tag a bundle's VERSION.txt names ("Version: v1.22.0"), or $null.
function Get-CaseBookVersionFromText([string] $Text) {
    if ($Text -match '(?m)^Version:\s*(\S+)\s*$' -and (Test-CaseBookReleaseTag $Matches[1])) { return $Matches[1] }
    return $null
}

# The SHA-256 a .sha256 file states (sha256sum's "<hash>  <name>", or the hash alone), or $null when it holds none.
function ConvertFrom-CaseBookSha256File([string] $Text) {
    if (-not $Text) { return $null }
    $first = ($Text.Trim() -split '\s+')[0]
    if ($first -match '^[0-9a-fA-F]{64}$') { return $first.ToUpperInvariant() }
    return $null
}

# --- Release integrity: the signature and the hash ---------------------------------------------------------------
# The Release workflow signs each bundle with CaseBook's release key (RSA-PSS, SHA-256, a 32-byte salt) and publishes
# casebook-<v>.zip.sig and casebook-<v>.zip.sha256 beside it. The scripts trust the public keys pinned in lib\CaseBookReleaseKeys.ps1
# (docs/decisions/0019-releases-are-signed-with-a-pinned-key.md).

# The keys a CaseBookReleaseKeys.ps1 pins, each @{ Id = '<16 hex>'; Xml = '<RSAKeyValue>...</RSAKeyValue>' }. A file that
# pins none, or no file, gives none.
function Get-CaseBookTrustedKeys([string] $Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $CaseBookReleaseKeys = @()
    . $Path
    return @(@($CaseBookReleaseKeys) | Where-Object { $_ -and $_.Id -and $_.Xml })
}

# An RSA object that does RSA-PSS on this PowerShell. Windows PowerShell 5.1's RSA.Create() is the CryptoAPI provider,
# which has no PSS, so it gets RSACng; PowerShell 7's RSA.Create() does PSS on every platform.
function New-CaseBookRsa {
    if ($PSVersionTable.PSEdition -eq 'Core') { return [System.Security.Cryptography.RSA]::Create() }
    return New-Object System.Security.Cryptography.RSACng
}

# A file's SHA-256 as bytes, read as a stream, since a bundle is large.
function Get-CaseBookFileSha256Bytes([string] $Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try { return , $sha.ComputeHash($stream) }
    finally { $stream.Dispose(); $sha.Dispose() }
}

# The id of the pinned key a signature verifies against, or $null when none does. $Sha256 is the signed file's SHA-256
# (Get-CaseBookFileSha256Bytes), $Signature the .sig file's bytes. A key that won't load is passed over.
function Test-CaseBookReleaseSignature([byte[]] $Sha256, [byte[]] $Signature, $Keys) {
    if (-not $Sha256 -or -not $Signature) { return $null }
    foreach ($key in @($Keys)) {
        $rsa = New-CaseBookRsa
        try {
            $rsa.FromXmlString([string]$key.Xml)
            if ($rsa.VerifyHash($Sha256, $Signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pss)) { return [string]$key.Id }
        } catch {
            Write-Verbose "Release key $($key.Id) couldn't be used: $($_.Exception.Message)"
        } finally { $rsa.Dispose() }
    }
    return $null
}

# The release tag a bundle's VERSION.txt names, or $null.
function Get-CaseBookBundleTag([string] $ZipPath) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $ZipPath).Path)
    try {
        $entry = $zip.Entries | Where-Object { $_.FullName -match '^[^/\\]+[/\\]VERSION\.txt$' -and $_.Length -lt 4096 } |
            Select-Object -First 1
        if (-not $entry) { return $null }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { return Get-CaseBookVersionFromText $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    } finally { $zip.Dispose() }
}

# Checks a bundle before anything in it is expanded or run, and throws (saying "Nothing was changed.") when it's refused.
#   The signature, <zip>.sig beside it: valid against a pinned key, it's CaseBook's release; present but not valid, it's
#   refused. Missing, it's refused when keys are pinned unless -AllowUnsigned (a bundle from before signing), and the
#   bundle is checked by its hash alone when none are.
#   The hash: -ExpectedSha256, else <zip>.sha256 beside it, must match. With neither, a bundle that isn't signed is
#   checked against its release's .sha256 on github.com when $Web (Invoke-WebRequest's parameters) is given; one that
#   can't be fetched is a warning.
# Returns Tag, KeyId (the key it's signed by, or $null), HashSource ('expected', 'local', 'release' or $null), Sha256,
# and the Notes and Warnings to show.
function Invoke-CaseBookBundleCheck {
    param(
        [Parameter(Mandatory = $true)] [string] $ZipPath,
        $Keys = @(),
        [switch] $AllowUnsigned,
        [string] $ExpectedSha256,
        [string] $Tag,
        [string] $Repository = 'jashley92/CaseBook',
        [hashtable] $Web,
        [string] $WorkDir = [IO.Path]::GetTempPath()
    )
    $Keys = @($Keys)
    $notes = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { throw "Bundle not found: $ZipPath" }
    $zipFull = (Resolve-Path -LiteralPath $ZipPath).Path
    $name = Split-Path -Leaf $zipFull
    if ($ExpectedSha256) {
        $ExpectedSha256 = $ExpectedSha256.Trim()
        if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw "-ExpectedSha256 must be the 64 hex characters of a SHA-256, not '$ExpectedSha256'. Nothing was changed."
        }
    }
    if (-not $Tag) {
        try { $Tag = Get-CaseBookBundleTag $zipFull }
        catch { $warnings.Add("Couldn't read VERSION.txt from the bundle ($($_.Exception.Message)).") }
    }
    $hashBytes = Get-CaseBookFileSha256Bytes $zipFull
    $actual = [BitConverter]::ToString($hashBytes).Replace('-', '')

    # 1. The signature.
    $keyId = $null
    $sigPath = "$zipFull.sig"
    if (Test-Path -LiteralPath $sigPath -PathType Leaf) {
        if ($Keys.Count -eq 0) {
            $notes.Add("$name.sig is beside it, but this script pins no release key to check it with, so it's checked by its SHA-256.")
        } else {
            $keyId = Test-CaseBookReleaseSignature $hashBytes ([IO.File]::ReadAllBytes($sigPath)) $Keys
            if (-not $keyId) {
                $ids = @($Keys | ForEach-Object { $_.Id }) -join ', '
                throw ("$name.sig isn't a valid signature of this bundle by CaseBook's release key ($ids): the bundle was changed " +
                       "after it was signed, or isn't CaseBook's. Nothing was changed. Download the bundle and its .sig from the release again.")
            }
            $notes.Add("Signed by CaseBook's release key $keyId.")
        }
    } elseif ($Keys.Count -gt 0) {
        if (-not $AllowUnsigned) {
            throw ("The bundle isn't signed: there's no $name.sig beside it. Copy the .sig from the release next to the zip. " +
                   "A release from before signing (v1.21.0 and earlier) has none; pass -AllowUnsigned to check it by its " +
                   "SHA-256 instead. Nothing was changed.")
        }
        $warnings.Add("The bundle isn't signed (no $name.sig). -AllowUnsigned: it's checked by its SHA-256 only.")
    }

    # 2. The hash.
    $hashSource = $null; $expected = $null; $from = $null
    if ($ExpectedSha256) {
        $expected = $ExpectedSha256.ToUpperInvariant(); $hashSource = 'expected'; $from = 'the -ExpectedSha256 given'
    } elseif (Test-Path -LiteralPath "$zipFull.sha256" -PathType Leaf) {
        $expected = ConvertFrom-CaseBookSha256File (Get-Content -LiteralPath "$zipFull.sha256" -Raw)
        if (-not $expected) { throw "$name.sha256 beside the bundle holds no SHA-256. Nothing was changed." }
        $hashSource = 'local'; $from = "$name.sha256 beside it"
    } elseif (-not $keyId) {
        if (-not $Tag) {
            $warnings.Add("The bundle doesn't name a release version, so its SHA-256 can't be checked against a release.")
        } elseif (-not $Web) {
            $warnings.Add("Not checked against a SHA-256. To check it, put casebook-$Tag.zip.sha256 from the release beside the zip, or pass -ExpectedSha256.")
        } else {
            $shaFile = Join-Path $WorkDir ("casebook-$Tag.zip.sha256." + [guid]::NewGuid().ToString('N'))
            $shaWeb = $Web.Clone(); $shaWeb.TimeoutSec = 30   # a host without github.com shouldn't wait long to find out
            $why = $null
            try {
                Invoke-WebRequest @shaWeb -Uri "https://github.com/$Repository/releases/download/$Tag/casebook-$Tag.zip.sha256" -OutFile $shaFile
                $expected = ConvertFrom-CaseBookSha256File (Get-Content -LiteralPath $shaFile -Raw)
                if (-not $expected) { $why = "the answer wasn't a .sha256" }
            } catch {
                $status = 0
                try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = 0 }
                $why = if ($status -eq 404) { "github.com/$Repository has no $Tag release with a .sha256" } else { "couldn't fetch it: $($_.Exception.Message)" }
            } finally { Remove-Item -LiteralPath $shaFile -ErrorAction SilentlyContinue }
            if ($expected) { $hashSource = 'release'; $from = "the $Tag release's on github.com/$Repository" }
            else {
                $warnings.Add("Not checked against the release ($why). Carrying on. To check it, put casebook-$Tag.zip.sha256 " +
                              "from the release beside the zip, or pass -ExpectedSha256.")
            }
        }
    }
    if ($expected) {
        if ($actual -ine $expected) {
            throw "The bundle's SHA-256 ($actual) doesn't match $from ($expected). Nothing was changed. Download the bundle from the release again."
        }
        $notes.Add("SHA-256 matches $($from): $actual")
    }
    return [pscustomobject]@{ Tag = $Tag; KeyId = $keyId; HashSource = $hashSource; Sha256 = $actual; Notes = @($notes); Warnings = @($warnings) }
}
