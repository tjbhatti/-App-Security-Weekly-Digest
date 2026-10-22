# ============================================================
# App Security Weekly Digest
# ============================================================

# ------------------------------------------------------------
# Connect to Microsoft Graph
# ------------------------------------------------------------

Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome

# Display connected tenant/account
$context = Get-MgContext

Write-Host ""
Write-Host "Connected Account : $($context.Account)" -ForegroundColor Cyan
Write-Host "Tenant ID         : $($context.TenantId)" -ForegroundColor Cyan
Write-Host ""


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

$today = Get-Date

# High-risk Microsoft Graph Application permissions
$highRiskPermissions = @(
    "Directory.ReadWrite.All"
    "Application.ReadWrite.All"
    "RoleManagement.ReadWrite.Directory"
    "User.ReadWrite.All"
    "Group.ReadWrite.All"
)


# ------------------------------------------------------------
# Initialise Counters
# ------------------------------------------------------------

$expiredSecrets = 0
$noOwnerApps    = 0
$oldAppsCount   = 0
$highRiskPerms  = 0


# ------------------------------------------------------------
# Initialise Result Collections
# ------------------------------------------------------------

$expiredSecretApps = @()
$noOwnerAppNames   = @()
$oldAppNames       = @()
$highRiskAppNames  = @()


# ------------------------------------------------------------
# Retrieve Applications
# ------------------------------------------------------------

$apps = Get-MgApplication -All

$graphSP = Get-MgServicePrincipal `
    -Filter "displayName eq 'Microsoft Graph'" `
    -Property "Id,DisplayName,AppRoles"

$servicePrincipals = Get-MgServicePrincipal `
    -All `
    -Property "Id,DisplayName,AppId"


# ------------------------------------------------------------
# Analyse App Registrations
# ------------------------------------------------------------

foreach ($app in $apps) {

    # --------------------------------------------------------
    # Check Application Age
    # --------------------------------------------------------

    if ($null -ne $app.CreatedDateTime) {

        $createdDate = [DateTime]$app.CreatedDateTime

        $appAgeDays = [int](
            New-TimeSpan -Start $createdDate -End $today
        ).TotalDays

        if ($appAgeDays -ge 365) {

            $oldAppsCount++

            $oldAppNames += [PSCustomObject]@{
                AppName     = $app.DisplayName
                AppId       = $app.AppId
                CreatedDate = $createdDate
                AgeDays     = $appAgeDays
            }
        }
    }


    # --------------------------------------------------------
    # Check Expired Secrets
    # --------------------------------------------------------

    foreach ($secret in $app.PasswordCredentials) {

        if ($null -eq $secret.EndDateTime) {
            continue
        }

        $endDate = [DateTime]$secret.EndDateTime

        if ($endDate -lt $today) {

            $expiredSecrets++

            $expiredSecretApps += [PSCustomObject]@{
                AppName    = $app.DisplayName
                AppId      = $app.AppId
                SecretName = $secret.DisplayName
                ExpiredOn  = $endDate
            }
        }
    }


    # --------------------------------------------------------
    # Check Application Owners
    # --------------------------------------------------------

    $owners = @(
        Get-MgApplicationOwner -ApplicationId $app.Id
    )

    if ($owners.Count -eq 0) {

        $noOwnerApps++

        $noOwnerAppNames += [PSCustomObject]@{
            AppName = $app.DisplayName
            AppId   = $app.AppId
        }
    }
}


# ------------------------------------------------------------
# Analyse Microsoft Graph Permissions
# ------------------------------------------------------------

foreach ($sp in $servicePrincipals) {

    $appRoles = @(
        Get-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $sp.Id
    )

    $foundHighRisk = $false
    $detectedPermissions = @()

    foreach ($role in $appRoles) {

        if ($role.ResourceDisplayName -ne "Microsoft Graph") {
            continue
        }

        $matchedRole = $graphSP.AppRoles |
            Where-Object { $_.Id -eq $role.AppRoleId }

        if ($null -eq $matchedRole) {
            continue
        }

        $permName = $matchedRole.Value

        if ($highRiskPermissions -contains $permName) {

            $foundHighRisk = $true
            $detectedPermissions += $permName
        }
    }

    if ($foundHighRisk) {

        $highRiskPerms++

        $highRiskAppNames += [PSCustomObject]@{
            AppName         = $sp.DisplayName
            AppId           = $sp.AppId
            HighRiskPermissions = (
                $detectedPermissions |
                Sort-Object -Unique
            ) -join ", "
        }
    }
}


# ------------------------------------------------------------
# Calculate Overall Risk
# ------------------------------------------------------------

$highFindings = 0

if ($expiredSecrets -gt 0) {
    $highFindings++
}

if ($noOwnerApps -gt 0) {
    $highFindings++
}

if ($oldAppsCount -gt 0) {
    $highFindings++
}

if ($highRiskPerms -gt 0) {
    $highFindings++
}


$overallRisk = if ($highFindings -ge 3) {

    "HIGH"

}
elseif ($highFindings -ge 1) {

    "MEDIUM"

}
else {

    "LOW"
}


# ============================================================
# DISPLAY RESULTS
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "              APP SECURITY WEEKLY DIGEST" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host ""

Write-Host "SUMMARY" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------"

Write-Host "Expired Secrets          : $expiredSecrets"
Write-Host "Applications With No Owner: $noOwnerApps"
Write-Host "Applications 365+ Days Old: $oldAppsCount"
Write-Host "High-Risk Applications    : $highRiskPerms"

Write-Host ""

$overallRiskColor = if ($overallRisk -eq "HIGH") {

    "Red"

}
elseif ($overallRisk -eq "MEDIUM") {

    "Yellow"

}
else {

    "Green"
}

Write-Host "OVERALL RISK: $overallRisk" -ForegroundColor $overallRiskColor


# ============================================================
# EXPIRED SECRETS
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "EXPIRED SECRETS" -ForegroundColor Red
Write-Host "============================================================"

if ($expiredSecretApps.Count -gt 0) {

    $expiredSecretApps |
        Sort-Object AppName |
        Format-Table `
            AppName,
            AppId,
            SecretName,
            ExpiredOn `
            -AutoSize

}
else {

    Write-Host "No expired secrets found." -ForegroundColor Green
}

# ============================================================
# OLD APPLICATIONS
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "APPLICATIONS 365+ DAYS OLD" -ForegroundColor Yellow
Write-Host "============================================================"
if ($oldAppNames.Count -gt 0) {

    $oldAppNames |
        Sort-Object AgeDays -Descending |
        Format-Table `
            AppName,
            AppId,
            CreatedDate,
            AgeDays `
            -AutoSize

}
else {

    Write-Host "No applications older than 365 days found." -ForegroundColor Green
}

# ============================================================
# HIGH-RISK GRAPH PERMISSIONS
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "HIGH-RISK MICROSOFT GRAPH PERMISSIONS" -ForegroundColor Red
Write-Host "============================================================"

if ($highRiskAppNames.Count -gt 0) {

    $highRiskAppNames |
        Sort-Object AppName |
        Format-Table `
            AppName,
            AppId,
            HighRiskPermissions `
            -Wrap `
            -AutoSize

}
else {

    Write-Host "No configured high-risk permissions found." -ForegroundColor Green
}


# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "FINAL SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================"

Write-Host "Expired Secrets           : $expiredSecrets"
Write-Host "Apps With No Owner        : $noOwnerApps"
Write-Host "Apps 365+ Days Old        : $oldAppsCount"
Write-Host "High-Risk Apps            : $highRiskPerms"
Write-Host "Findings Triggered        : $highFindings"
Write-Host ""
Write-Host "Overall Risk              : $overallRisk" `
    -ForegroundColor $overallRiskColor

Write-Host ""