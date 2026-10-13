# AD group-name helpers shared by New-CaseBookConfig.ps1 and Install-CaseBook.ps1.
#
# BUG-224: CaseBook maps a bare group name ("SOC-Analysts") only to that group in the web server's own domain
# (BUG-188: a name is unique only within its domain). So the installers write each group as DOMAIN\Group, taken from
# the group itself, and say so when that domain isn't the server's, where a bare name would map nobody.

function Resolve-CaseBookGroup([string] $name) {
    # Returns the group's own DOMAIN\Group name and its domain SID, or $null when it can't be resolved from here.
    $candidates = if ($name -match '\\') { @($name) } else { @($name, "$env:USERDOMAIN\$name") }
    foreach ($c in $candidates) {
        try {
            $sid = ([System.Security.Principal.NTAccount]::new($c)).Translate([System.Security.Principal.SecurityIdentifier])
            $canonical = $sid.Translate([System.Security.Principal.NTAccount]).Value
            return [pscustomobject]@{ Name = $canonical; DomainSid = $sid.AccountDomainSid }
        } catch { }
    }
    return $null
}

function Get-ServerDomainSid {
    # This computer's domain (its machine account's domain SID), or $null off a domain or when AD can't be reached.
    try {
        $sid = ([System.Security.Principal.NTAccount]::new("$env:COMPUTERNAME$")).Translate([System.Security.Principal.SecurityIdentifier])
        return $sid.AccountDomainSid
    } catch { return $null }
}

function ConvertTo-CaseBookGroupName([string] $role, [string] $name, [switch] $OnWebServer) {
    # The name to store for a role's group: DOMAIN\Group when it resolves, else the name as given, with a note.
    $resolved = Resolve-CaseBookGroup $name
    if ($null -eq $resolved) {
        Write-Host "    NOTE: couldn't resolve the $role group '$name' from here - confirm it exists in AD." -ForegroundColor Yellow
        if ($name -notmatch '\\') {
            Write-Host "          A bare name maps only a group in the web server's own domain; write DOMAIN\Group otherwise." -ForegroundColor Yellow
        }
        return $name
    }
    if ($resolved.Name -ne $name) { Write-Host "    $role group: $($resolved.Name)" -ForegroundColor Gray }
    if ($OnWebServer -and $resolved.DomainSid) {
        $server = Get-ServerDomainSid
        if ($server -and $resolved.DomainSid -ne $server) {
            Write-Host "    NOTE: $($resolved.Name) is in another domain than this server; it maps by that full name." -ForegroundColor Yellow
        }
    }
    return $resolved.Name
}
