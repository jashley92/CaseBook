# IIS helpers shared by Install-CaseBook.ps1 and Upgrade-CaseBook.ps1.
#
# REV-71/REV-72: Stop-WebAppPool only asks the pool to stop. Its worker (w3wp) finishes open requests, Blazor circuits
# and background jobs first, and holds the app's DLLs until it exits, so copying files straight after (a fixed few
# seconds' wait) fails on locked files part way through.

function Stop-CaseBookAppPool([string] $Name, [int] $TimeoutSeconds = 120) {
    # Stops the pool and waits until it reports Stopped and its worker process has exited. Throws if it doesn't in time.
    Import-Module WebAdministration -ErrorAction Stop
    if (-not (Test-Path "IIS:\AppPools\$Name")) { return }
    if ((Get-WebAppPoolState -Name $Name).Value -ne 'Stopped') { Stop-WebAppPool -Name $Name }
    $pattern = '-ap\s+"' + [regex]::Escape($Name) + '"'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = (Get-WebAppPoolState -Name $Name).Value
        $workers = @(Get-CimInstance Win32_Process -Filter "Name = 'w3wp.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -match $pattern })
        if ($state -eq 'Stopped' -and $workers.Count -eq 0) { return }
        Start-Sleep -Seconds 2
    }
    throw ("The app pool '$Name' didn't stop within $TimeoutSeconds seconds: its worker process still holds the app's " +
           "files. Stop the pool in IIS Manager (or end its w3wp.exe), then re-run.")
}
