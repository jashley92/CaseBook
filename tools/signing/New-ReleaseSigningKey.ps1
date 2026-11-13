#Requires -Version 5.1

<#
.SYNOPSIS
    Makes CaseBook's release signing key: sets it as the RELEASE_SIGNING_KEY secret and pins its public key in the repo.

.DESCRIPTION
    Run once, by the owner, on a workstation, from a branch of this repository (docs/development/releasing.md):
      1. Generates an RSA-3072 key pair (.NET; PowerShell 7, or Windows PowerShell 5.1).
      2. Writes the private key, as PEM (PKCS#8), to -BackupPath, which must not exist. Keep that file offline or in a
         password manager: it's the only copy outside GitHub, and anyone with it can sign a bundle every CaseBook install
         trusts.
      3. Sets the repository secret RELEASE_SIGNING_KEY by piping the PEM to 'gh secret set', so the key is never shown
         and never in shell history. Needs the GitHub CLI, signed in with rights to the repository's secrets.
      4. Adds the public key to deploy/lib/CaseBookReleaseKeys.ps1, as RSA XML with its id (the first 16 hex characters of
         the SHA-256 of its SubjectPublicKeyInfo, what 'openssl pkey -pubout -outform DER | sha256sum' gives).
    It prints only the key id and what to do next. Commit CaseBookReleaseKeys.ps1 and merge it before tagging a release:
    the Release workflow refuses to sign with a key the repository doesn't pin.

.PARAMETER BackupPath
    Where to write the private key (PEM). Refused if the file exists.

.PARAMETER Repository
    The repository whose secret is set (default 'jashley92/CaseBook').

.PARAMETER KeysPath
    The CaseBookReleaseKeys.ps1 to add the public key to (default deploy/lib/CaseBookReleaseKeys.ps1 in this repository).

.PARAMETER Rotate
    For a key rotation: write the backup and pin the new key, but leave the secret as it is, so the next release is
    still signed by the old key and carries the new one to every install that upgrades to it. Set the secret afterwards
    (the script prints the command).

.PARAMETER DryRun
    For testing: generate and write the backup and the public key, but never run gh. Needs -KeysPath (a copy, not the
    repository's file).

.EXAMPLE
    pwsh tools/signing/New-ReleaseSigningKey.ps1 -BackupPath E:\casebook-release-key.pem
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BackupPath,
    [string] $Repository = 'jashley92/CaseBook',
    [string] $KeysPath,
    [switch] $Rotate,
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$repoKeys = Join-Path (Join-Path (Join-Path $repoRoot 'deploy') 'lib') 'CaseBookReleaseKeys.ps1'
$marker = '# --- New-ReleaseSigningKey.ps1 adds each key above this line ---'

if ($DryRun -and -not $KeysPath) { throw "-DryRun needs -KeysPath: a copy of CaseBookReleaseKeys.ps1 to write to, not the repository's." }
if (-not $KeysPath) { $KeysPath = $repoKeys }
if (-not (Test-Path -LiteralPath $KeysPath -PathType Leaf)) {
    if (-not $DryRun) { throw "Not found: $KeysPath" }
    Copy-Item -LiteralPath $repoKeys -Destination $KeysPath
}
$keysText = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $KeysPath).Path)
if (-not $keysText.Contains($marker)) { throw "$KeysPath has no line '$marker' to add the key above." }
$BackupPath = [IO.Path]::GetFullPath($BackupPath)
if (Test-Path -LiteralPath $BackupPath) { throw "$BackupPath exists. Give a new file: this script never overwrites a key." }
if (-not (Test-Path -LiteralPath (Split-Path -Parent $BackupPath) -PathType Container)) { throw "The folder for $BackupPath doesn't exist." }
if ($Repository -notmatch '^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$') { throw "-Repository must be owner/name, not '$Repository'." }

$setSecret = -not $DryRun -and -not $Rotate
if ($setSecret) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "The GitHub CLI (gh) isn't on PATH. Install it and run 'gh auth login' first." }
    & gh auth status *> $null
    if ($LASTEXITCODE -ne 0) { throw "gh isn't signed in. Run 'gh auth login', then this script again." }
}

# --- DER, for the PEM and the key id (by hand, so this runs on Windows PowerShell 5.1 as well as PowerShell 7) -----
function Get-DerLength([int] $n) {
    if ($n -lt 0x80) { return , [byte[]]@($n) }
    $b = New-Object System.Collections.Generic.List[byte]
    while ($n -gt 0) { $b.Insert(0, [byte]($n -band 0xFF)); $n = $n -shr 8 }
    $b.Insert(0, [byte](0x80 + $b.Count))
    return , $b.ToArray()
}
function New-Der([int] $Tag, [object[]] $Parts) {
    $content = New-Object System.Collections.Generic.List[byte]
    foreach ($p in $Parts) { $content.AddRange([byte[]]$p) }
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add([byte]$Tag); $out.AddRange([byte[]](Get-DerLength $content.Count)); $out.AddRange($content)
    return , $out.ToArray()
}
function New-DerInteger([byte[]] $Unsigned) {
    $i = 0
    while ($i -lt $Unsigned.Length - 1 -and $Unsigned[$i] -eq 0) { $i++ }
    $v = New-Object System.Collections.Generic.List[byte]
    if ($Unsigned[$i] -band 0x80) { $v.Add([byte]0) }
    for (; $i -lt $Unsigned.Length; $i++) { $v.Add($Unsigned[$i]) }
    return New-Der 0x02 @(, $v.ToArray())
}
$rsaAlgorithm = [byte[]](0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00)   # rsaEncryption, NULL

$rsa = if ($PSVersionTable.PSEdition -eq 'Core') { [System.Security.Cryptography.RSA]::Create(3072) } else { New-Object System.Security.Cryptography.RSACng 3072 }
try {
    $p = $rsa.ExportParameters($true)
    $pkcs1 = New-Der 0x30 @((New-DerInteger ([byte[]]@(0))), (New-DerInteger $p.Modulus), (New-DerInteger $p.Exponent),
        (New-DerInteger $p.D), (New-DerInteger $p.P), (New-DerInteger $p.Q), (New-DerInteger $p.DP), (New-DerInteger $p.DQ),
        (New-DerInteger $p.InverseQ))
    $pkcs8 = New-Der 0x30 @((New-DerInteger ([byte[]]@(0))), $rsaAlgorithm, (New-Der 0x04 @(, $pkcs1)))
    $publicKey = New-Der 0x30 @((New-DerInteger $p.Modulus), (New-DerInteger $p.Exponent))
    $bitString = New-Object System.Collections.Generic.List[byte]
    $bitString.Add([byte]0); $bitString.AddRange($publicKey)
    $spki = New-Der 0x30 @($rsaAlgorithm, (New-Der 0x03 @(, $bitString.ToArray())))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $keyId = ([BitConverter]::ToString($sha.ComputeHash($spki)).Replace('-', '').ToLowerInvariant()).Substring(0, 16)
    $sha.Dispose()
    $xml = $rsa.ToXmlString($false)

    $b64 = [Convert]::ToBase64String($pkcs8)
    $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
    $pem = "-----BEGIN PRIVATE KEY-----`n" + ($lines -join "`n") + "`n-----END PRIVATE KEY-----`n"
    [Array]::Clear($pkcs1, 0, $pkcs1.Length); [Array]::Clear($pkcs8, 0, $pkcs8.Length)
} finally { $rsa.Dispose() }

if ($keysText -match "Id\s*=\s*'$keyId'") { throw "Key $keyId is already pinned in $KeysPath." }

# The backup: explanatory text above the PEM block, which openssl and .NET both pass over.
$note = "CaseBook release signing key $keyId (RSA-3072, PKCS#8), made $([DateTime]::UtcNow.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)).`n" +
        "Keep this file offline or in a password manager, and nowhere else. Anyone with it can sign a bundle CaseBook installs trust.`n" +
        "It's the RELEASE_SIGNING_KEY secret of $Repository. Its public key is pinned in deploy/lib/CaseBookReleaseKeys.ps1.`n"
[IO.File]::WriteAllText($BackupPath, $note + $pem, (New-Object System.Text.ASCIIEncoding))

if ($setSecret) {
    $pem | & gh secret set RELEASE_SIGNING_KEY --repo $Repository
    if ($LASTEXITCODE -ne 0) {
        $pem = $null
        throw ("'gh secret set' failed (exit $LASTEXITCODE). The key is saved at $BackupPath, and not pinned. Delete that file " +
               "and run this script again.")
    }
}
$pem = $null

# Pin the public key: one line above the marker, kept in the file's own line endings.
$eol = if ($keysText.Contains("`r`n")) { "`r`n" } else { "`n" }
$added = [DateTime]::UtcNow.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
$entry = "    @{ Id = '$keyId'; Added = '$added'; Xml = '$xml' }"
$at = $keysText.IndexOf($marker)
$lineStart = $keysText.LastIndexOf("`n", $at) + 1
$keysText = $keysText.Substring(0, $lineStart) + $entry + $eol + $keysText.Substring($lineStart)
[IO.File]::WriteAllText((Resolve-Path -LiteralPath $KeysPath).Path, $keysText, (New-Object System.Text.ASCIIEncoding))

Write-Host "Release signing key $keyId"
Write-Host "  Private key: $BackupPath. Move it offline or into a password manager now, and delete any other copy."
if ($setSecret) { Write-Host "  Secret:      RELEASE_SIGNING_KEY set on $Repository." }
Write-Host "  Public key:  pinned in $KeysPath."
Write-Host ''
Write-Host 'Next:'
if ($DryRun) {
    Write-Host '  Dry run: gh wasn''t run and the repository''s CaseBookReleaseKeys.ps1 wasn''t changed.'
} elseif ($Rotate) {
    Write-Host '  1. Commit deploy/lib/CaseBookReleaseKeys.ps1, open a pull request and merge it.'
    Write-Host '  2. Release as usual: that release is still signed by the old key, and carries the new one.'
    Write-Host '  3. Then switch the secret to the new key:'
    Write-Host "       Get-Content -Raw '$BackupPath' | gh secret set RELEASE_SIGNING_KEY --repo $Repository"
} else {
    Write-Host '  1. Commit deploy/lib/CaseBookReleaseKeys.ps1, open a pull request and merge it.'
    Write-Host '  2. Tag the next release. The Release workflow signs the bundle and publishes casebook-<v>.zip.sig.'
}
