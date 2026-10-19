# Server-side settings the upgrade adds to an older appsettings.Production.json when they're missing, so an administrator
# can find and set them there. Each is server configuration only (never in the in-app settings). The value written is the
# release's own appsettings.json value, which the app already uses while the setting is absent, so adding it changes
# nothing until someone edits it. A setting already present is never changed.

# Sections (or single settings) to fill in. Each must exist in src\IncidentManager.Web\appsettings.json (a test checks).
function Get-CaseBookServerSettingPaths {
    return @(
        'Storage:Encryption', 'Config:TrustedBundleKeys',
        'Integrity:SigningKey', 'Integrity:RetiredPublicKeysPath', 'Integrity:ChainKey', 'Integrity:SealCopies',
        'Secrets:CyberArk', 'Siem', 'Chat:Webhook', 'Updates:Repository', 'Updates:Proxy', 'Agenda:FeedKey',
        'RateLimiting:Downloads', 'BackupStatus:BackupMaxAgeHours', 'BackupStatus:RestoreMaxAgeDays',
        'Email:SmtpHost', 'Email:SmtpPort', 'Email:EnableSsl', 'Email:SmtpTimeoutSeconds')
}

# Left out: secrets an administrator enters in Administration (CAP-40), where they're encrypted. Set in this file
# they'd win over the form.
function Get-CaseBookServerSettingExclusions { return @('Siem:Webhook:Token', 'Chat:Webhook:WebhookUrl') }

function Test-CaseBookJsonPath($Node, [string] $Path) {
    foreach ($part in $Path.Split(':')) {
        if ($null -eq $Node -or $Node -isnot [System.Management.Automation.PSCustomObject] -or -not $Node.PSObject.Properties[$part]) { return $false }
        $Node = $Node.$part
    }
    return $true
}

function Get-CaseBookJsonNode($Node, [string] $Path) {
    foreach ($part in $Path.Split(':')) {
        if ($null -eq $Node -or $Node -isnot [System.Management.Automation.PSCustomObject] -or -not $Node.PSObject.Properties[$part]) { return $null }
        $Node = $Node.$part
    }
    return ,$Node   # the comma keeps a list a list (a returned array would be unrolled)
}

# Every setting (a leaf: a value or a list) under the listed paths in $Defaults that $Live lacks.
function Find-CaseBookMissingServerSettings($Live, $Defaults) {
    $excluded = Get-CaseBookServerSettingExclusions
    $leaves = New-Object System.Collections.Generic.List[string]
    function Add-Leaves($node, [string] $path) {
        if ($node -is [System.Management.Automation.PSCustomObject]) {
            foreach ($p in $node.PSObject.Properties) {
                if ($p.Name.StartsWith('//')) { continue }
                Add-Leaves $p.Value "${path}:$($p.Name)"
            }
        } else { $leaves.Add($path) }
    }
    foreach ($path in Get-CaseBookServerSettingPaths) {
        if (-not (Test-CaseBookJsonPath $Defaults $path)) { continue }
        Add-Leaves (Get-CaseBookJsonNode $Defaults $path) $path
    }
    return @($leaves | Where-Object { $excluded -notcontains $_ -and -not (Test-CaseBookJsonPath $Live $_) })
}

# Adds each of $Paths (from Find-CaseBookMissingServerSettings) to $Live with its $Defaults value. A section created on
# the way gets its explanation: the template's, else the release appsettings.json's.
function Add-CaseBookServerSettings($Live, $Defaults, $Template, [string[]] $Paths) {
    foreach ($path in $Paths) {
        $parts = $path.Split(':')
        $node = $Live
        for ($i = 0; $i -lt $parts.Length - 1; $i++) {
            if (-not $node.PSObject.Properties[$parts[$i]]) {
                $section = [pscustomobject]@{}
                $at = ($parts[0..$i]) -join ':'
                $note = Get-CaseBookJsonNode $Template "${at}://"
                if ($null -eq $note) { $note = Get-CaseBookJsonNode $Defaults "${at}://" }
                if ($note -is [string]) { $section | Add-Member -NotePropertyName '//' -NotePropertyValue $note }
                $node | Add-Member -NotePropertyName $parts[$i] -NotePropertyValue $section
            }
            $node = $node.($parts[$i])
            if ($node -isnot [System.Management.Automation.PSCustomObject]) { throw "appsettings.Production.json: $(($parts[0..$i]) -join ':') isn't a section, so $path can't be added under it." }
        }
        $value = Get-CaseBookJsonNode $Defaults $path
        $node | Add-Member -NotePropertyName $parts[-1] -NotePropertyValue $value
    }
}
