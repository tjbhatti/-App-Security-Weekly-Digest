Connect-MgGraph -Scopes "Application.Read.All"
$apps              = Get-MgApplication -All
$graphSP           = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -Property "Id,AppRoles"
$servicePrincipals = Get-MgServicePrincipal -All -Property "Id,DisplayName,AppId"
$today = Get-Date
foreach ($app in $apps) {
    $appAgeDays = [int]($today - $app.CreatedDateTime).TotalDays
    if ($appAgeDays -ge 365) { $oldAppsCount++ }

    foreach ($secret in $app.PasswordCredentials) {
        if (-not $secret.EndDateTime) { continue }
      $endDate = [DateTime]$secret.EndDateTime
        $daysLeft = [int](New-TimeSpan -Start $today -End $endDate).TotalDays
        if ($daysLeft -lt 0) { $expiredSecrets++ }
    }

    $owners = Get-MgApplicationOwner -ApplicationId $app.Id
    if ($owners.Count -eq 0) { $noOwnerApps++ }
}
foreach ($sp in $servicePrincipals) {
    $appRoles      = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
    $foundHighRisk = $false

    foreach ($role in $appRoles) {
        if ($role.ResourceDisplayName -ne "Microsoft Graph") { continue }
        $permName = ($graphSP.AppRoles | Where-Object Id -eq $role.AppRoleId).Value
        if ($highRiskPermissions -contains $permName) {
            $foundHighRisk = $true
            break
        }
    }

    if ($foundHighRisk) { $highRiskPerms++ }
}
$permName = ($graphSP.AppRoles | Where-Object Id -eq $role.AppRoleId).Value
$highFindings = 0
if ($expiredSecrets -gt 0) { $highFindings++ }
if ($noOwnerApps -gt 0)    { $highFindings++ }
if ($oldAppsCount -gt 0)   { $highFindings++ }
if ($highRiskPerms -gt 0)  { $highFindings++ }

$overallRisk = if ($highFindings -ge 3) 
   { "HIGH" }
               elseif ($highFindings -ge 1) 
               { "MEDIUM" }
               else  
                                     { "LOW" }

Write-Host "  Expired secrets : $expiredSecrets $(if ($expiredSecrets -gt 0) { '🔴' } else { '✅' })" -ForegroundColor $(if ($expiredSecrets -gt 0) { "Red" } else { "Green" })