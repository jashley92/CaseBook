# Date stamps for file names and records the deploy scripts write. Dot-source this file.
#
# BUG-600: Get-Date's Format parameter and a ToString date pattern use the server's culture, whose calendar can be Thai Buddhist
# (year 2569) or Hijri (1448), so stamps written on such a server sorted out of order with the rest and
# Verify-LedgerDigests.ps1 -Latest picked the wrong digests. Every stamp goes through here, in the invariant culture.
# ASCII only: Windows PowerShell 5.1 misreads non-ASCII in BOM-less files.

function Get-CaseBookStamp {
    param(
        [string] $Format = 'yyyyMMdd-HHmmss',
        [switch] $Utc,
        [datetime] $When = [datetime]::Now
    )
    $t = if ($Utc) { $When.ToUniversalTime() } else { $When }
    return $t.ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-CaseBookStamp {
    # The instant a 'yyyyMMdd-HHmmss' stamp names, or $null when $Text holds none (a file named by hand).
    param([string] $Text, [string] $Format = 'yyyyMMdd-HHmmss')
    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParseExact($Text, $Format, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None, [ref] $parsed)
    if ($ok) { return $parsed }
    return $null
}
