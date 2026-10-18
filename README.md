# 🔐 App Security Weekly Digest
### Microsoft Entra ID | PowerShell | Microsoft Graph API

> Combines five app registration security checks into a single weekly
> digest — total apps, expired secrets, apps with no owners, old apps,
> and apps with high risk permissions. Prints a clean formatted dashboard
> with an overall risk score combining all findings.

---

### Why App Registration Security Matters

App registrations are one of the most overlooked attack surfaces
in Microsoft 365 environments:
Expired secrets → production outages and broken integrations
No owner assigned → nobody rotating credentials or watching the app
Old abandoned apps → forgotten attack surface nobody is monitoring
High risk permissions → compromised app can read all email or write all users

A single compromised app with `User.ReadWrite.All` gives an attacker
the ability to modify every user in the tenant — more damage than a
compromised regular user account.

---

## 📄 Executive Summary

**Problem:** Organizations create app registrations and never review them.
Secrets expire with nobody notified. Apps accumulate without owners.
Old integrations nobody uses remain active. High risk permissions get
granted and forgotten. Nobody has weekly visibility into app security
health without manually checking multiple portal screens.

**Solution:** This script runs five checks in a single execution and
produces a one-page digest — ready to share with the security team
every Friday morning.

**Result:** Complete app security health picture in under 10 minutes.

**Time to value:** Under 10 minutes from first run to digest ready.

---

## 🔍 Real Findings From Lab Tenant

| Metric | Result |
|---|---|
| Total app registrations | 37 |
| Expired secrets | 2 🔴 |
| Apps with no owner | 34 🔴 |
| Apps older than 365 days | 0 ✅ |
| High risk permissions | 1 🔴 |
| Overall risk | HIGH |

**34 out of 37 apps had no owner assigned** — nobody responsible
for rotating credentials or maintaining these applications.

---

## 🔍 Overall Risk Calculation

| Findings Flagged | Risk Level |
|---|---|
| 3 or more | HIGH |
| 1 or 2 | MEDIUM |
| 0 | LOW |
  
---

## ✅ Step by Step Breakdown

**Step 1 — Connected to Microsoft Graph**
```powershell
Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome
```
- One scope covers app registrations, service principals, and owners
- `Application.Read.All` — read all app registrations and service principals

---

**Step 2 — Initialized counters**
```powershell
$totalApps      = 0
$expiredSecrets = 0
$noOwnerApps    = 0
$oldAppsCount   = 0
$highRiskPerms  = 0
```
- Five counters — one per check
- No results list needed — counters only
- Incremented with `++` as findings are discovered

---

**Step 3 — Pulled all data before loops**
```powershell
$apps              = Get-MgApplication -All -Property "..."
$graphSP           = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -Property "Id,AppRoles"
$servicePrincipals = Get-MgServicePrincipal -All -Property "Id,DisplayName,AppId"
```
- All three data sets pulled ONCE before any loop
- `$graphSP` holds the Microsoft Graph service principal which contains all permission definitions
- Pulling inside the loop would make 37+ redundant API calls

---

**Step 4 — Checked app age, expired secrets, and owners per app**
```powershell
foreach ($app in $apps) {
    $appAgeDays = [int]($today - $app.CreatedDateTime).TotalDays
    if ($appAgeDays -ge 365) { $oldAppsCount++ }

    foreach ($secret in $app.PasswordCredentials) {
        if (-not $secret.EndDateTime) { continue }
        $daysLeft = [int]($secret.EndDateTime - $today).TotalDays
        if ($daysLeft -lt 0) { $expiredSecrets++ }
    }

    $owners = Get-MgApplicationOwner -ApplicationId $app.Id
    if ($owners.Count -eq 0) { $noOwnerApps++ }
}
```
- Three checks run for every app — no early `continue` that would skip checks
- Null check on `EndDateTime` — some credentials have no expiry date
- Negative `$daysLeft` means the secret is already expired
- `$owners.Count -eq 0` catches apps with nobody assigned as owner

---

**Step 5 — Checked high risk permissions per service principal**
```powershell
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
```
- Separate loop from the app loop — service principals are different objects
- Filter to Microsoft Graph permissions only — other resources have different permission names
- Permission name not available directly — must look up GUID against `$graphSP.AppRoles`
- Boolean flag `$foundHighRisk` — set to true on first high risk permission found
- `break` exits inner loop immediately — no point checking remaining permissions
- One counter increment per SP — even if it has multiple high risk permissions

---

**Step 6 — Why permission name lookup is needed**
```powershell
$permName = ($graphSP.AppRoles | Where-Object Id -eq $role.AppRoleId).Value
```
- `Get-MgServicePrincipalAppRoleAssignment` returns the permission as a GUID only
- The human readable name like `User.ReadWrite.All` lives in the Microsoft Graph SP's AppRoles
- Match the GUID from the assignment to the GUID in Graph's AppRoles to get the name
- Without this lookup you can only see GUIDs — not readable permission names

---

**Step 7 — Calculated overall risk**
```powershell
$highFindings = 0
if ($expiredSecrets -gt 0) { $highFindings++ }
if ($noOwnerApps -gt 0)    { $highFindings++ }
if ($oldAppsCount -gt 0)   { $highFindings++ }
if ($highRiskPerms -gt 0)  { $highFindings++ }

$overallRisk = if ($highFindings -ge 3)    { "HIGH" }
               elseif ($highFindings -ge 1) { "MEDIUM" }
               else                         { "LOW" }
```
- Each finding category counts as one point regardless of how many apps are affected
- Three or more categories flagged — HIGH risk
- One or two categories — MEDIUM risk
- Nothing flagged — LOW risk

---

**Step 8 — Printed digest with dynamic colors**
```powershell
Write-Host "  Expired secrets : $expiredSecrets $(if ($expiredSecrets -gt 0) { '🔴' } else { '✅' })" -ForegroundColor $(if ($expiredSecrets -gt 0) { "Red" } else { "Green" })
```
- Each line changes color based on whether the finding exists
- Green with checkmark when clean — red with circle when flagged
- Overall risk printed in matching color at the bottom

---

# PowerShell printed results

<img width="438" height="220" alt="Screenshot 2026-10-17 at 20 47 43" src="https://github.com/user-attachments/assets/2589df30-de2f-4b13-a5e1-fa83fba9e317" />

---

## 📋 Compliance Relevance

| Framework | Control |
|---|---|
| NIST 800-53 | AC-2 — Account Management |
| SOC 2 Type II | CC6.1 — Logical Access Controls |
| ISO 27001 | A.9.2.3 — Management of Privileged Access Rights |
| CIS Controls | Control 5 — Account Management |
| Microsoft Secure Score | Ensure app registrations have owners |

---

## 🎯 Use Cases

**Weekly Security Review**
Run every Friday to give the security team a one-page
view of app registration security health.

**M&A Tenant Discovery**
Run on day one of an acquisition to immediately understand
the app security posture of the acquired tenant.

**Audit Preparation**
Run before an audit to identify and remediate app security
gaps before auditors find them.

**Incident Response**
Run immediately after a suspected breach to understand
current app credential and permission exposure.
