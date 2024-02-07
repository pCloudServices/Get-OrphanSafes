###########################################################################
#
# NAME: Get-OrphanedSafes
#
# AUTHOR:  Mike Brook<mike.brook@cyberark.com>
#
# COMMENT: 
# Script will attempt to check which safes are fully manageable, segregated managealbe, and lastly orphan (meaning no way to access or manage the safe).
#
#
###########################################################################
param(
    [ValidateScript({
        If(![string]::IsNullOrEmpty($_)) {
            $isValid = ($_ -like "*.privilegecloud.cyberark.cloud*") -or ($_ -like "*.cyberark.cloud*") -or ($_ -like "*.privilegecloud.cyberark.com*") -or ($_ -like "*.cyberark.com*")
            if (-not $isValid) {
                throw "Invalid URL format. Please specify a valid Privilege Cloud tenant URL (e.g.https://<subdomain>.cyberark.cloud)."
            }
            $true
        }
        Else {
            $true
        }
    })]
    [Parameter(Mandatory = $true, HelpMessage = "Specify the URL of the Privilege Cloud tenant (e.g., https://<subdomain>.cyberark.cloud)")]
    [string]$PortalURL,
    [Parameter(Mandatory = $true, HelpMessage = "Specify a User that has at minimum Audit permissions.")]
    [PSCredential]$Credentials,
    [Parameter(Mandatory = $false, HelpMessage = "Enter a file path for bulk safes")]
    [ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid })]
    [ValidatePattern('\.(csv|txt)$')]
    [Alias("File")]
    [String]$SafesFromFile,
    [Parameter(Mandatory = $False)]
    [ValidateSet("cyberark","identity")]
    [string]$ForceAuthType,
    [Parameter(Mandatory = $False, HelpMessage = "Specify the execution mode: BasicAudit or ComprehensiveAudit.")]
    [ValidateSet("BasicAudit","ComprehensiveAudit")]
    [string]$ExecutionMode
)


# Modules
$mainModule = "Import_AllModules.psm1"

$modulePaths = @(
"..\\PS-Modules\\$mainModule",
"..\\..\\PS-Modules\\$mainModule",
".\\PS-Modules\\$mainModule", 
".\\$mainModule"
"..\\$mainModule"
".\\..\\$mainModule"
"..\\..\\$mainModule"
)

foreach ($modulePath in $modulePaths) {

    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -ErrorAction Stop -DisableNameChecking -Force
        } catch {
            Write-Host "Failed to import module from $modulePath. Error: $_"
            Write-Host "check that you copied the PS-Modules folder correctly."
            Pause
            Exit
        }
     }
}

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_Get-OrphanedSafes.log"

[int]$scriptVersion = 2

# PS Window title
$Host.UI.RawUI.WindowTitle = "Privilege Cloud Get OrphanedSafes Script"

## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

# Minimal permissions required to fully control a safe, ("Manage safe" or "Manage Safe Members" is not enough unfortunately).
$global:SafePermissionsMinimum = @(
    "useAccounts",
    "retrieveAccounts",
    "listAccounts",
    "addAccounts",
    "updateAccountContent",
    "updateAccountProperties",
    "initiateCPMAccountManagementOperations",
    "specifyNextAccountContent",
    "renameAccounts",
    "deleteAccounts",
    "unlockAccounts",
    "manageSafe",
    "manageSafeMembers",
    "viewAuditLog",
    "viewSafeMembers",
    "accessWithoutConfirmation"
)


# Builtin safes to exclude
$excludeBuiltInSafes = @(
    'Notification Engine',
    'Pictures',
    'System',
    'VaultInternal',
    'Telemetry_Config',
    'SharedAuth_Internal',
    'AccountsFeedADAccounts',
    'AccountsFeedDiscoveryLogs',
    'PasswordManager Safe',
    'PasswordManagerShared Safe',
    'PasswordManager_Pending',
    'PasswordManagerTemp',
    'PVWAConfig',
    'PVWAUserPrefs',
    'PVWATicketingSystem',
    'PVWAPrivateUserPrefs',
    'PVWAReports',
    'PVWATaskDefinitions',
    'PVWAPublicData',
    'PSMSessions',
    'PSMLiveSessions',
    'PSMUnmanagedSessionAccounts',
    'PSMNotifications',
    'PSMUniversalConnectors',
    'PSMPConf',
    'PSMPLiveSessions',
    'PSMPADBUserProfile',
    'PSMPADBridgeCustom',
    'PSMPADBridgeConf',
    'AppProviderCacheSafe',
    'TelemetryConfig'
)

$excludeBuiltInUsers = @(
    'Master',
    'Batch',
    'Backup Users',
    'Operators',
    'Notification Engines',
    'PSMAppUsers',
    'DR Users',
    'CyberarkAccountsIntegration',
    'Auditors'
)

$global:SafeManagerPermissions = @(
    "listAccounts", "addAccounts", "updateAccountContent", "updateAccountProperties",
    "initiateCPMAccountManagementOperations", "renameAccounts",
    "deleteAccounts", "unlockAccounts", "manageSafe", "manageSafeMembers", "viewSafeMembers"
)

$global:EndUserPermissions = @(
    "useAccounts", "retrieveAccounts", "listAccounts"
)

Function Export-SafeDataToCsv {
    param(
        [Parameter(Mandatory = $true)]
        $Owner,

        [Parameter(Mandatory = $true)]
        [string]$OutputCsvPath
    )

    [PSCustomObject]@{
        Safe = $Owner.safeName
        memberName = $Owner.memberName -join ', '
        memberType = $Owner.memberType -join ', '
        useAccounts = $Owner.permissions.useAccounts -join ', '
        retrieveAccounts = $Owner.permissions.retrieveAccounts -join ', '
        listAccounts = $Owner.permissions.listAccounts -join ', '
        addAccounts = $Owner.permissions.addAccounts -join ', '
        updateAccountContent = $Owner.permissions.updateAccountContent -join ', '
        updateAccountProperties = $Owner.permissions.updateAccountProperties -join ', '
        initiateCPMAccountManagementOperations = $Owner.permissions.initiateCPMAccountManagementOperations -join ', '
        specifyNextAccountContent = $Owner.permissions.specifyNextAccountContent -join ', '
        renameAccounts = $Owner.permissions.renameAccounts -join ', '
        deleteAccounts = $Owner.permissions.deleteAccounts -join ', '
        unlockAccounts = $Owner.permissions.unlockAccounts -join ', '
        manageSafe = $Owner.permissions.manageSafe -join ', '
        manageSafeMembers = $Owner.permissions.manageSafeMembers -join ', '
        backupSafe = $Owner.permissions.backupSafe -join ', '
        viewAuditLog = $Owner.permissions.viewAuditLog -join ', '
        viewSafeMembers = $Owner.permissions.viewSafeMembers -join ', '
        accessWithoutConfirmation = $Owner.permissions.accessWithoutConfirmation -join ', '
        createFolders = $Owner.permissions.createFolders -join ', '
        deleteFolders = $Owner.permissions.deleteFolders -join ', '
        moveAccountsAndFolders = $Owner.permissions.moveAccountsAndFolders -join ', '
        requestsAuthorizationLevel1 = $Owner.permissions.requestsAuthorizationLevel1 -join ', '
        requestsAuthorizationLevel2 = $Owner.permissions.requestsAuthorizationLevel2 -join ', '
    } | Export-Csv -Delimiter "," -Path $OutputCsvPath -Append -Force -NoTypeInformation
}



# Init filenames
$output_SafesNotFound = "$ScriptLocation\$($PlatformTenantId)_$(Get-Date -Format 'yyyy-MM-dd_HH\hmm\m') Safes Not Found.csv"
$output_OrphanedSafes = "$ScriptLocation\$($PlatformTenantId)_$(Get-Date -Format 'yyyy-MM-dd_HH\hmm\m') Safes Orphaned.csv"
$output_RecoverableFullAccessSafes = "$ScriptLocation\$($PlatformTenantId)_$(Get-Date -Format 'yyyy-MM-dd_HH\hmm\m') Safes Full permissions.csv"
$output_RecoverableCombinedAccessSafes = "$ScriptLocation\$($PlatformTenantId)_$(Get-Date -Format 'yyyy-MM-dd_HH\hmm\m') Safes Combined permissions.csv"
$output_UnableToAccessSafes = "$ScriptLocation\$($PlatformTenantId)_$(Get-Date -Format 'yyyy-MM-dd_HH\hmm\m') Safes Unable To Access.csv"

# Check files don't exist before every run.
if (Test-Path $output_SafesNotFound) {
    Remove-Item $output_SafesNotFound -Force
}
if (Test-Path $output_OrphanedSafes) {
    Remove-Item $output_OrphanedSafes -Force
}
if (Test-Path $output_RecoverableFullAccessSafes) {
    Remove-Item $output_RecoverableFullAccessSafes -Force
}
if (Test-Path $output_UnableToAccessSafes) {
    Remove-Item $output_UnableToAccessSafes -Force
}
if (Test-Path $output_RecoverableFullAccessSafes) {
    Remove-Item $output_RecoverableFullAccessSafes -Force
}


Function Check-RequiredPermissionsFULL {
    param (
        [PSCustomObject]$permissions
    )
    
    $hasRequiredPermissions = $true
    foreach ($perm in $global:SafePermissionsMinimum) {
        if (-not $permissions.$perm) {
            $hasRequiredPermissions = $false
            break
        }
    }
    
    return $hasRequiredPermissions
}

Function Check-SegregatedManageable {
    param (
        [Parameter(Mandatory = $true)]
        $SafeMembers # Array of objects representing the members and their permissions
    )

    $safeManagerGroups = @()
    $endUserEntities = @() # Can be users or groups

    foreach ($member in $SafeMembers) {
        if ($member.memberType -eq "User" -and $member.isPredefinedUser -eq $false) {
            # Check if this user can be considered as an End User
            $isEndUser = $member.permissions.listAccounts -eq $true -and 
                         ($member.permissions.useAccounts -eq $true -or $member.permissions.retrieveAccounts -eq $true)

            if ($isEndUser) {
                $endUserEntities += $member
            }
        }
        elseif ($member.memberType -eq "Group") {
            # Check for Safe Manager permissions within groups
            $isSafeManager = $true
            foreach ($perm in $global:SafeManagerPermissions) {
                if (-not $member.permissions.$perm -eq $true) {
                    $isSafeManager = $false
                    break
                }
            }

            if ($isSafeManager) {
                $safeManagerGroups += $member
            }
            # Also check if group can be considered as an End User
            $isEndUser = $member.permissions.listAccounts -eq $true -and 
                         ($member.permissions.useAccounts -eq $true -or $member.permissions.retrieveAccounts -eq $true)

            if ($isEndUser) {
                $endUserEntities += $member
            }
        }
    }

    # Ensure segregation: at least one group must be a Safe Manager and at least one entity (user or group) must be an End User
    if ($safeManagerGroups -and $endUserEntities) {
        return @{
            SafeManagers = $safeManagerGroups
            EndUsers = $endUserEntities
        }
    }
    else {
        return $null
    }
}


Function FilterOutBuiltInSafes ($safes){
      Write-LogMessage -type Info -MSG "Filtering Builtin Safes" -Early
      # Dynamically identify base names of CPM safes and add to exclusion list
      $dynamicSafePatterns = @('_Workspace$', '_Info$', '_ADInternal$', '_Accounts$', '_Pending')
      $baseNames = @()
      
      foreach ($safe in $safes) {
          foreach ($pattern in $dynamicSafePatterns) {
              if ($safe -match $pattern) {
                  # Extract base name by removing the dynamic part
                  $baseName = $safe -replace $pattern, ''
                  $baseNames += $baseName
                  break
              }
          }
      }
      
      $baseNames = $baseNames | Select-Object -Unique
      
      # Combine lists
      $combinedExclusions = $excludeBuiltInSafes + $baseNames

      # Init count
      $originalCount = $safes.Count
   
      # Filter the $safes array
      $filteredSafes = $safes | Where-Object {
      $safe = $_
      $exclude = $false

      # Check for combined exclusions
      if ($combinedExclusions -contains $safe) {
          $exclude = $true
      }

      # Handle CPM patterns
      foreach ($pattern in $dynamicSafePatterns) {
          if ($safe -match $pattern) {
              $exclude = $true
              break
          }
      }

      # Exclude the safe if $exclude is true
      -not $exclude
      }
      $filteredOutCount = $originalCount - $filteredSafes.Count
      Write-LogMessage -type Info -MSG "Filtered out $($filteredOutCount) BuiltIn safes" -Early

      return $filteredSafes
}



# Main
Try{

    # Select mode if not ran from command line
    if (-not $ExecutionMode) {
        $ExecutionMode = Get-Choice -Title "Select Execution Mode" -Options @("BasicAudit", "ComprehensiveAudit")
        Write-LogMessage -type Info -MSG "Running in $($ExecutionMode) mode." -Early
        Start-Sleep 2
        Write-LogMessage -type Warning -MSG "You should run the script with -BasicAudit or -ComprehensiveAudit flag to skip this prompt each time."
        Start-Sleep 5
    }

    # Build PVWA Urls
    $platformURLs = DetermineTenantTypeURLs -PortalURL $PortalURL
    $IdentityAPIURL = $platformURLs.IdentityURL
    $pvwaAPI = $platformURLs.PVWA_API_URLs.PVWAAPI
    
    # Auditor related
    $URL_UsersGroups = $pvwaAPI + "/UserGroups"
    $URL_UserSetGroup = $URL_UsersGroups + "/{0}/Members"
    $URL_UserDelGroup = $URL_UsersGroups + "/{0}/Members/{1}"

    # Login
    if($ForceAuthType){
        $logonheader = Authenticate-Platform -platformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType
    }Else{
        $logonheader = Authenticate-Platform -platformURLs $platformURLs -creds $Credentials
    }
    if(-not($logonheader.Authorization)){
        Write-Host "Failed to get Token, exiting..."
        Exit
    }

    # Check if user has Safe Auditors permissions
    $Get_CurrentAuditorGroupAndMembers = Get-AuditorsGroup -URLAPI $pvwaAPI -logonheader $logonheader
    Write-LogMessage -type Info -MSG "Checking if user: $($Credentials.UserName) has Safe Auditor permissions.." -Early
    if ($Get_CurrentAuditorGroupAndMembers.members.username -contains $Credentials.UserName){
        Write-LogMessage -type Info -MSG "User has Auditor permission, proceeding." -Early
    }Else{
        Write-LogMessage -type Warning -MSG "User $($Credentials.UserName) doesn't have Auditor permissions, please be advised you may not see all available safes."
        $userDecision = Read-Host "You do not have Auditor permissions. Do you want to continue anyway? (Y/N)"
        if ($userDecision -ne 'Y') {
            Write-LogMessage -type Info -MSG "User chose not to proceed. Exiting script." -Early
            Pause
            Exit
        }
        else{
            Write-LogMessage -type Info -MSG "User chose to proceed." -Early
        }
    }

    # Insert/Remove user from Auditors group
      ##$AuditorsId = (Get-AuditorsGroup -URLAPI $pvwaAPI -logonheader $logonHeader).id
      ##Insert-AuditorsGroup -UsernameToAdd $Credentials.UserName -URLAPI $pvwaAPI -AuditorsId $AuditorsId -logonheader $logonheader

    if (-not($SafesFromFile)) {
        $validChoice = $false
    
        do {
            Write-Host "=====================================================" -ForegroundColor Cyan
            Write-LogMessage -type Warning -MSG "Since you didn't provide a file using the -SafesFromFile flag when you ran the script."
            Write-LogMessage -type Warning -MSG "Here are the other options you can choose from: "
            Write-Host "=====================================================" -ForegroundColor Cyan
    
            Write-Host "1. Provide a filename now." -ForegroundColor Magenta
            Write-Host "2. Type the safename manually (multiple safes can be typed using ',' comma char)." -ForegroundColor Magenta
            Write-Host "3. Select specific safes from all available Safes in the vault." -ForegroundColor Magenta
            Write-Host "4. Check all available Safes in the vault." -ForegroundColor Magenta
            Write-Host "Q. Press Q to quit." -ForegroundColor Red
            Write-Host "=====================================================" -ForegroundColor Cyan
    
            $choice = Read-Host "Please enter your choice (1-4) or Q to quit"
    
            switch ($choice) {
                "1" {
                    Write-Host "You chose to provide a filename: $filename" -ForegroundColor Green
                    $validChoice = $true
                    $Safes = gc $(Get-UserFile)
                }
                "2" {
                    $safenamesInput = Read-Host "Type the safename(s) manually, separated by commas"
                    $safes = $safenamesInput -split ',\s*'
                    Write-Host "You chose to manually type safename(s): $safenamesInput" -ForegroundColor Green
                    $validChoice = $true
                }
                "3" {
                    Write-Host "You chose to get all Safes and select specific ones." -ForegroundColor Green
                    $validChoice = $true
                    $Get_Safes = Get-Safes -URLAPI $pvwaAPI -logonHeader $logonheader
                    # Filter builtin before showing the option
                    $filteredSafes = FilterOutBuiltInSafes $($Get_Safes.safename)
                    Write-LogMessage -type Info -MSG "Safes count after filter $($filteredSafes.count)" -Early
                    $safes = $filteredSafes | Out-GridView -PassThru -Title "Select Safes"
                    if ($safes) {
                        Write-Host "You have selected the following safes:" -ForegroundColor Green
                        $safes | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
                    } else {
                        Write-Host "No safes were selected." -ForegroundColor Red
                    }
                }
    
                "4" {
                    Write-Host "You chose to get all Safes and work on them." -ForegroundColor Green
                    $validChoice = $true
                    $Get_Safes = Get-Safes -URLAPI $pvwaAPI -logonHeader $logonheader
                    $filteredSafes = FilterOutBuiltInSafes $($Get_Safes.safename)
                    Write-LogMessage -type Info -MSG "Safes count after filter $($filteredSafes.count)" -Early
                    $safes = $filteredSafes
                }
                "Q" {
                    Write-Host "Quitting..." -ForegroundColor Red
                    $validChoice = $true
                    Exit
                }
                default {
                    Write-Host "Invalid choice. Please select a valid option." -ForegroundColor Red
                }
            }
        } while (-not $validChoice)
        } else {
            if (Test-Path -Path $SafesFromFile) {
                $Safes = Get-Content $SafesFromFile
            } else {
                Write-Host "The file path '$SafesFromFile' does not exist or is not accessible." -ForegroundColor Red
                exit
            }
        }
    
    # filter out PPA (Personal Privileged Account) safes as these are personal safes and shouldn't be passed to another person.
    Write-LogMessage -type Info -MSG "Filtering out all the PPA (Personal Privileged Account) Safes" -Early
    $safes = $safes | where {$_ -notlike "PPA_I_*"}
    Write-LogMessage -type Info -MSG "Safes count after filter $($safes.count)" -Early
    Start-Sleep 2

    # Iterate through the list provided and get member details and permissions for each safe and store it in a variable.
    Write-LogMessage -type Info -MSG "Start checking safes." -Early
    Foreach ($Safe in $safes){
        $ownersList = $null
        $safeOwnersFULL = $null
        $safeOwners = $null
        $segregatedManageable = $null

        Try
        {
            # Get Owner list for each Safe
            $ownersList = Invoke-RestMethod -Uri ("$pvwaAPI/Safes/$($safe)/Members?filter=includePredefinedUsers eq true") -Method Get -Headers $logonHeader -ContentType "application/json" -ErrorVariable pvwaERR
        }
        Catch
        {
            write-host $_.ErrorDetails.Message -ForegroundColor Gray
            # In case of acess errors
            if($_.ErrorDetails.Message -like "*unauthorized to view owners*"){
                    Write-LogMessage -type Warning -MSG "Unable to process safe $safe"
                    Write-Host ""
                    [PSCustomObject]@{
                    Safe = $Safe
                    ErrorDisplay = $_.ErrorDetails.Message
                    } | Export-Csv -Delimiter "," $output_UnableToAccessSafes -Append -Force -NoTypeInformation
                    $WarningAccess = $true
            }
            Elseif($_.ErrorDetails.Message -like "*was not found*"){
               Write-LogMessage -type Warning -MSG "Safe '$($safe)' not found!"
                [PSCustomObject]@{
                    SafeNotFound = $Safe
                    } | Export-Csv -Delimiter "," $output_SafesNotFound -Append -Force -NoTypeInformation
                Write-Host ""
            }   
            Else{
                Write-Host "Couldn't get Safe owners for safe '$($safe)', fix it and rerun the script"
                Write-Host ""
            }
        }
            # Check Owner permissions
            $safeOwners = $ownersList.value | where {$_.safeName -eq $safe -and ($_.memberName -notin $excludeBuiltInUsers)} | select safeName,memberName,memberType,permissions
            $safeOwnersFULL = $ownersList.value | where {$_.safeName -eq $Safe -and (Check-RequiredPermissionsFULL -permissions $_.permissions) -and ($_.memberName -notin $excludeBuiltInUsers)} | select safeName,memberName,memberType,permissions
            $segregatedManageable = $ownersList.value | where {$_.safeName -eq $Safe -and (Check-SegregatedManageable -SafeMembers $ownersList.value) -and ($_.memberName -notin $excludeBuiltInUsers)} | select safeName,memberName,memberType,permissions
            
            # If any owners have full permissions to manage safe.
            if($ExecutionMode -and $safeOwnersFULL){
                Write-Host "Safe '$($Safe)' is OK, it has the following member/s that can manage it:" -ForegroundColor Green
                $($safeOwnersFULL.memberName) | Write-host -ForegroundColor blue -BackgroundColor Gray
                Write-Host ""
                foreach($owner in $safeOwnersFULL){               
                    Export-SafeDataToCsv -Owner $owner -OutputCsvPath $output_RecoverableFullAccessSafes
                }
            }
            ElseIf($ExecutionMode -eq "ComprehensiveAudit" -and ($segregatedManageable) -and ($ownersList)){
                write-host "Safe '$($Safe)' is OK, it has the following" -ForegroundColor Green -NoNewline ; Write-Host " Combination " -ForegroundColor Yellow -BackgroundColor Magenta -NoNewline;Write-Host  "of member/s that can manage it:" -ForegroundColor Green
                $($segregatedManageable.memberName) | Write-host -ForegroundColor blue -BackgroundColor Gray
                Write-Host ""
                foreach($owner in $segregatedManageable){               
                    Export-SafeDataToCsv -Owner $owner -OutputCsvPath $output_RecoverableCombinedAccessSafes
                }
            }
             # If we got some type of response but the owners list we're looking for comes back empty, safe is orphan.
            Elseif(($safeOwnersFULL -eq $null) -and ($segregatedManageable -eq $null) -and ($ownersList)){
                $safeOwners = $ownersList.value | where {$_.safeName -eq $safe -and ($_.memberName -notin $excludeBuiltInUsers)} | select safeName,memberName,memberType,permissions
                #$safeOwners = $ownersList.value | where {$_.safeName -eq $safe} | select safeName,memberName,memberType,permissions
                Write-Host "Safe '$($Safe)' is Orphaned" -ForegroundColor Red
                Write-Host ""
                if ($safeOwners -eq $null){
                    [PSCustomObject]@{
                        Safe = $Safe
                        memberName = "** NO SAFE OWNERS FOUND **"  
                    } | Export-Csv -Delimiter "," $output_OrphanedSafes -Append -Force -NoTypeInformation
                }
                Else
                {
                    foreach($owner in $safeOwners){               
                        Export-SafeDataToCsv -Owner $owner -OutputCsvPath $output_OrphanedSafes
                    }
                }
          }
    }
    # In case permission related errors, lets tell the user they should address those.
    Write-Host ""
    Write-Host "***"
    Write-LogMessage -type Success -MSG "****** Results saved under `"$ScriptLocation`" ******"
    Write-Host "***"
    if($WarningAccess){
        Write-LogMessage -type Warning -MSG "We noticed some safes were inaccessible, you should run the script with a user that has Audit permissions"
    }
}
Catch{
        # Output the terminating error
        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri))"
}
Finally{
        # In case command errors in the middle of the loop, lets logoff and clean creds
        ##Try{Extract-AuditorsGroup -UsernameToRemove $Credentials.UserName -URLAPI $pvwaAPI -AuditorsId $AuditorsId -logonheader $logonheader}Catch{}
        # Logoff
        Try{Invoke-RestMethod -Uri $URL_PVWALogoff -Method Post -Headers $logonHeader | Out-Null}Catch{}
}

# SIG # Begin signature block
# MIIqRgYJKoZIhvcNAQcCoIIqNzCCKjMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAiEa9MFXdcM4O5
# 4iZECoPEqtNi1cySdrTYmbSPkW25SqCCGFcwggROMIIDNqADAgECAg0B7l8Wnf+X
# NStkZdZqMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
# bG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9i
# YWxTaWduIFJvb3QgQ0EwHhcNMTgwOTE5MDAwMDAwWhcNMjgwMTI4MTIwMDAwWjBM
# MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xv
# YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRf
# JMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpi
# Lx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR
# 5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hp
# sk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Sa
# er9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaOCASIwggEeMA4GA1Ud
# DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSP8Et/qC5FJK5N
# UPpjmove4t0bvDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzA9Bggr
# BgEFBQcBAQQxMC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL3Jvb3RyMTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL3Jvb3QuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIB
# FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG
# 9w0BAQsFAAOCAQEAI3Dpz+K+9VmulEJvxEMzqs0/OrlkF/JiBktI8UCIBheh/qvR
# XzzGM/Lzjt0fHT7MGmCZggusx/x+mocqpX0PplfurDtqhdbevUBj+K2myIiwEvz2
# Qd8PCZceOOpTn74F9D7q059QEna+CYvCC0h9Hi5R9o1T06sfQBuKju19+095VnBf
# DNOOG7OncA03K5eVq9rgEmscQM7Fx37twmJY7HftcyLCivWGQ4it6hNu/dj+Qi+5
# fV6tGO+UkMo9J6smlJl1x8vTe/fKTNOvUSGSW4R9K58VP3TLUeiegw4WbxvnRs4j
# vfnkoovSOWuqeRyRLOJhJC2OKkhwkMQexejgcDCCBaIwggSKoAMCAQICEHgDGEJF
# cIpBz28BuO60qVQwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2ln
# biBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkds
# b2JhbFNpZ24wHhcNMjAwNzI4MDAwMDAwWhcNMjkwMzE4MDAwMDAwWjBTMQswCQYD
# VQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xv
# YmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9vdCBSNDUwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC2LcUw3Xroq5A9A3KwOkuZFmGy5f+lZx03HOV+7JODqoT1
# o0ObmEWKuGNXXZsAiAQl6fhokkuC2EvJSgPzqH9qj4phJ72hRND99T8iwqNPkY2z
# BbIogpFd+1mIBQuXBsKY+CynMyTuUDpBzPCgsHsdTdKoWDiW6d/5G5G7ixAs0sdD
# HaIJdKGAr3vmMwoMWWuOvPSrWpd7f65V+4TwgP6ETNfiur3EdaFvvWEQdESymAfi
# dKv/aNxsJj7pH+XgBIetMNMMjQN8VbgWcFwkeCAl62dniKu6TjSYa3AR3jjK1L6h
# wJzh3x4CAdg74WdDhLbP/HS3L4Sjv7oJNz1nbLFFXBlhq0GD9awd63cNRkdzzr+9
# lZXtnSuIEP76WOinV+Gzz6ha6QclmxLEnoByPZPcjJTfO0TmJoD80sMD8IwM0kXW
# LuePmJ7mBO5Cbmd+QhZxYucE+WDGZKG2nIEhTivGbWiUhsaZdHNnMXqR8tSMeW58
# prt+Rm9NxYUSK8+aIkQIqIU3zgdhVwYXEiTAxDFzoZg1V0d+EDpF2S2kUZCYqaAH
# N8RlGqocaxZ396eX7D8ZMJlvMfvqQLLn0sT6ydDwUHZ0WfqNbRcyvvjpfgP054d1
# mtRKkSyFAxMCK0KA8olqNs/ITKDOnvjLja0Wp9Pe1ZsYp8aSOvGCY/EuDiRk3wID
# AQABo4IBdzCCAXMwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFB8Av0aACvx4ObeltEPZVlC7zpY7
# MB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHoGCCsGAQUFBwEBBG4w
# bDAtBggrBgEFBQcwAYYhaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vcm9vdHIz
# MDsGCCsGAQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2Vy
# dC9yb290LXIzLmNydDA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2Jh
# bHNpZ24uY29tL3Jvb3QtcjMuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsG
# AQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAN
# BgkqhkiG9w0BAQwFAAOCAQEArPfMFYsweagdCyiIGQnXHH/+hr17WjNuDWcOe2LZ
# 4RhcsL0TXR0jrjlQdjeqRP1fASNZhlZMzK28ZBMUMKQgqOA/6Jxy3H7z2Awjuqgt
# qjz27J+HMQdl9TmnUYJ14fIvl/bR4WWWg2T+oR1R+7Ukm/XSd2m8hSxc+lh30a6n
# sQvi1ne7qbQ0SqlvPfTzDZVd5vl6RbAlFzEu2/cPaOaDH6n35dSdmIzTYUsvwyh+
# et6TDrR9oAptksS0Zj99p1jurPfswwgBqzj8ChypxZeyiMgJAhn2XJoa8U1sMNSz
# BqsAYEgNeKvPF62Sk2Igd3VsvcgytNxN69nfwZCWKb3BfzCCBugwggTQoAMCAQIC
# EHe9DgW3WQu2HUdhUx4/de0wDQYJKoZIhvcNAQELBQAwUzELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24g
# Q29kZSBTaWduaW5nIFJvb3QgUjQ1MB4XDTIwMDcyODAwMDAwMFoXDTMwMDcyODAw
# MDAwMFowXDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MjAwBgNVBAMTKUdsb2JhbFNpZ24gR0NDIFI0NSBFViBDb2RlU2lnbmluZyBDQSAy
# MDIwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyyDvlx65ATJDoFup
# iiP9IF6uOBKLyizU/0HYGlXUGVO3/aMX53o5XMD3zhGj+aXtAfq1upPvr5Pc+OKz
# GUyDsEpEUAR4hBBqpNaWkI6B+HyrL7WjVzPSWHuUDm0PpZEmKrODT3KxintkktDw
# tFVflgsR5Zq1LLIRzyUbfVErmB9Jo1/4E541uAMC2qQTL4VK78QvcA7B1MwzEuy9
# QJXTEcrmzbMFnMhT61LXeExRAZKC3hPzB450uoSAn9KkFQ7or+v3ifbfcfDRvqey
# QTMgdcyx1e0dBxnE6yZ38qttF5NJqbfmw5CcxrjszMl7ml7FxSSTY29+EIthz5hV
# oySiiDby+Z++ky6yBp8mwAwBVhLhsoqfDh7cmIsuz9riiTSmHyagqK54beyhiBU8
# wurut9itYaWvcDaieY7cDXPA8eQsq5TsWAY5NkjWO1roIs50Dq8s8RXa0bSV6KzV
# SW3lr92ba2MgXY5+O7JD2GI6lOXNtJizNxkkEnJzqwSwCdyF5tQiBO9AKh0ubcdp
# 0263AWwN4JenFuYmi4j3A0SGX2JnTLWnN6hV3AM2jG7PbTYm8Q6PsD1xwOEyp4Lk
# tjICMjB8tZPIIf08iOZpY/judcmLwqvvujr96V6/thHxvvA9yjI+bn3eD36blcQS
# h+cauE7uLMHfoWXoJIPJKsL9uVMCAwEAAaOCAa0wggGpMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBQlndD8WQmGY8Xs87ETO1ccA5I2ETAfBgNVHSMEGDAWgBQfAL9GgAr8eDm3
# pbRD2VZQu86WOzCBkwYIKwYBBQUHAQEEgYYwgYMwOQYIKwYBBQUHMAGGLWh0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NTBGBggrBgEF
# BQcwAoY6aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvY29kZXNp
# Z25pbmdyb290cjQ1LmNydDBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NS5jcmwwVQYDVR0gBE4wTDBB
# BgkrBgEEAaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2ln
# bi5jb20vcmVwb3NpdG9yeS8wBwYFZ4EMAQMwDQYJKoZIhvcNAQELBQADggIBACV1
# oAnJObq3oTmJLxifq9brHUvolHwNB2ibHJ3vcbYXamsCT7M/hkWHzGWbTONYBgIi
# ZtVhAsVjj9Si8bZeJQt3lunNcUAziCns7vOibbxNtT4GS8lzM8oIFC09TOiwunWm
# dC2kWDpsE0n4pRUKFJaFsWpoNCVCr5ZW9BD6JH3xK3LBFuFr6+apmMc+WvTQGJ39
# dJeGd0YqPSN9KHOKru8rG5q/bFOnFJ48h3HAXo7I+9MqkjPqV01eB17KwRisgS0a
# Ifpuz5dhe99xejrKY/fVMEQ3Mv67Q4XcuvymyjMZK3dt28sF8H5fdS6itr81qjZj
# yc5k2b38vCzzSVYAyBIrxie7N69X78TPHinE9OItziphz1ft9QpA4vUY1h7pkC/K
# 04dfk4pIGhEd5TeFny5mYppegU6VrFVXQ9xTiyV+PGEPigu69T+m1473BFZeIbuf
# 12pxgL+W3nID2NgiK/MnFk846FFADK6S7749ffeAxkw2V4SVp4QVSDAOUicIjY6i
# vSLHGcmmyg6oejbbarphXxEklaTijmjuGalJmV7QtDS91vlAxxCXMVI5NSkRhyTT
# xPupY8t3SNX6Yvwk4AR6TtDkbt7OnjhQJvQhcWXXCSXUyQcAerjH83foxdTiVdDT
# HvZ/UuJJjbkRcgyIRCYzZgFE3+QzDiHeYolIB9r1MIIHbzCCBVegAwIBAgIMcE3E
# /BY6leBdVXwMMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUg
# RVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDAeFw0yMjAyMTUxMzM4MzVaFw0yNTAyMTUx
# MzM4MzVaMIHUMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjESMBAGA1UE
# BRMJNTEyMjkxNjQyMRMwEQYLKwYBBAGCNzwCAQMTAklMMQswCQYDVQQGEwJJTDEQ
# MA4GA1UECBMHQ2VudHJhbDEUMBIGA1UEBxMLUGV0YWggVGlrdmExEzARBgNVBAkT
# CjkgSGFwc2Fnb3QxHzAdBgNVBAoTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xHzAd
# BgNVBAMTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4wggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDys9frIBUzrj7+oxAS21ansV0C+r1R+DEGtb5HQ225eEqe
# NXTnOYgvrOIBLROU2tCq7nKma5qA5bNgoO0hxYQOboC5Ir5B5mmtbr1zRdhF0h/x
# f/E1RrBcsZ7ksbqeCza4ca1yH2W3YYsxFYgucq+JLqXoXToc4CjD5ogNw0Y66R13
# Km94WuowRs/tgox6SQHpzb/CF0fMNCJbpXQrzZen1dR7Gtt2cWkpZct9DCTONwbX
# GZKIdBSmRIfjDYDMHNyz42J2iifkUQgVcZLZvUJwIDz4+jkODv/++fa2GKte06po
# L5+M/WlQbua+tlAyDeVMdAD8tMvvxHdTPM1vgj11zzK5qVxgrXnmFFTe9knf9S2S
# 0C8M8L97Cha2F5sbvs24pTxgjqXaUyDuMwVnX/9usgIPREaqGY8wr0ysHd6VK4wt
# o7nroiF2uWnOaPgFEMJ8+4fRB/CSt6OyKQYQyjSUSt8dKMvc1qITQ8+gLg1budzp
# aHhVrh7dUUVn3N2ehOwIomqTizXczEFuN0siQJx+ScxLECWg4X2HoiHNY7KVJE4D
# L9Nl8YvmTNCrHNwiF1ctYcdZ1vPgMPerFhzqDUbdnCAU9Z/tVspBTcWwDGCIm+Yo
# 9V458g3iJhNXi2iKVFHwpf8hoDU0ys30SID/9mE3cc41L+zoDGOMclNHb0Y5CQID
# AQABo4IBtjCCAbIwDgYDVR0PAQH/BAQDAgeAMIGfBggrBgEFBQcBAQSBkjCBjzBM
# BggrBgEFBQcwAoZAaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# Z3NnY2NyNDVldmNvZGVzaWduY2EyMDIwLmNydDA/BggrBgEFBQcwAYYzaHR0cDov
# L29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNvZGVzaWduY2EyMDIwMFUG
# A1UdIAROMEwwQQYJKwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3
# Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMAkGA1UdEwQCMAAw
# RwYDVR0fBEAwPjA8oDqgOIY2aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9nc2dj
# Y3I0NWV2Y29kZXNpZ25jYTIwMjAuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8G
# A1UdIwQYMBaAFCWd0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTRWDsgBgAr
# Xx8j10jVgqJYDQPVsTANBgkqhkiG9w0BAQsFAAOCAgEAU50DXmYXBEgzng8gv8EN
# mr1FT0g75g6UCgBhMkduJNj1mq8DWKxLoS11gomB0/8zJmhbtFmZxjkgNe9cWPvR
# NZa992pb9Bwwwe1KqGJFvgv3Yu1HiVL6FYzZ+m0QKmX0EofbwsFl6Z0pLSOvIESr
# ICa4SgUk0OTDHNBUo+Sy9qm+ZJjA+IEK3M/IdNGjkecsFekr8tQEm7x6kCArPoug
# mOetMgXhTxGjCu1QLQjp/i6P6wpgTSJXf9PPCxMmynsxBKGggs+vX/vl9CNT/s+X
# Z9sz764AUEKwdAdi9qv0ouyUU9fiD5wN204fPm8h3xBhmeEJ25WDNQa8QuZddHUV
# hXugk2eHd5hdzmCbu9I0qVkHyXsuzqHyJwFXbNBuiMOIfQk4P/+mHraq+cynx6/2
# a+G8tdEIjFxpTsJgjSA1W+D0s+LmPX+2zCoFz1cB8dQb1lhXFgKC/KcSacnlO4SH
# oZ6wZE9s0guXjXwwWfgQ9BSrEHnVIyKEhzKq7r7eo6VyjwOzLXLSALQdzH66cNk+
# w3yT6uG543Ydes+QAnZuwQl3tp0/LjbcUpsDttEI5zp1Y4UfU4YA18QbRGPD1F9y
# wjzg6QqlDtFeV2kohxa5pgyV9jOyX4/x0mu74qADxWHsZNVvlRLMUZ4zI4y3KvX8
# vZsjJFVKIsvyCgyXgNMM5Z4xghFFMIIRQQIBATBsMFwxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdD
# QyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMAIMcE3E/BY6leBdVXwMMA0GCWCG
# SAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIAPCCnrUbtqBA1pq0Jjiia9aCZBxn1Hn7FXOUCD0CeQ0MA0GCSqGSIb3
# DQEBAQUABIICAAlOxfN/UkvcaRr7WAMi/2c2JcEsCGw04rZUUuMRAeRuJCs1OrQN
# yqBGxWeMj4CowRMx4c16BfrqPoGfnn5fX3GGOpLSv9leeCa3x1vgAXLAcVrci1j9
# 0C0FjSq1E2CjzbetArI5S2TrfdjZKyqxXdpDgkp1KWqpFGXnCwN5lclOjy7CIwD9
# 0Ag/t2N/lD48lEzl6IgWN8qFqk7muC9f+/CY6mAHnn48BYOj7JoVj3apTjnkCm6O
# jlHhHNeaHWkSygkAD84B7UCIQb+KA7dPCDZNCfjJfN/MhY7WjRt5B4kfh7q21xib
# GL1O8l8rE/vU76mnEfC3me681WY1r5vNCXJ1qE3bwThmiHLxA2x89mr451Q+JO1S
# MujdW/rGqIS2PrQ53FzPg19vfZePj/3TnC8NBGeSg+Humfh6xtea1+jTuHghhw7B
# VFyN/K5nQIh2VuNL1HONGcZNjD6m81K4u/7hF8MMA22Ex/zhHXsIGqjTFrpXWKmx
# 2UsgSaaxIG59O/okmi5IBTZHFIkcT4VY1UGuLqMR5FfTHCn9Oiil4e/OJuVbSffE
# GGb2l93Sl8+oJ6x4K3SRL79P3/BcUH8oTYsK/YF7zDMQ9Uh4XpEqAeIghZSAg8lo
# dM+CjzhNfIv6TeQIhEvhmhPX7XmOjrRMHZ0ApiIOxr7s2bFVCzJ034XEoYIOLDCC
# DigGCisGAQQBgjcDAwExgg4YMIIOFAYJKoZIhvcNAQcCoIIOBTCCDgECAQMxDTAL
# BglghkgBZQMEAgEwgf8GCyqGSIb3DQEJEAEEoIHvBIHsMIHpAgEBBgtghkgBhvhF
# AQcXAzAhMAkGBSsOAwIaBQAEFPjg6UhkwWDVsx0XzTZtPkYDcJhBAhUAqXY5ku4H
# tEg9sJYaH9Mg4FqtmeIYDzIwMjQwMjA3MjI0NDExWjADAgEeoIGGpIGDMIGAMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV
# BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNI
# QTI1NiBUaW1lU3RhbXBpbmcgU2lnbmVyIC0gRzOgggqLMIIFODCCBCCgAwIBAgIQ
# ewWx1EloUUT3yYnSnBmdEjANBgkqhkiG9w0BAQsFADCBvTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVz
# dCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBWZXJpU2lnbiwgSW5jLiAtIEZv
# ciBhdXRob3JpemVkIHVzZSBvbmx5MTgwNgYDVQQDEy9WZXJpU2lnbiBVbml2ZXJz
# YWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNjAxMTIwMDAwMDBa
# Fw0zMTAxMTEyMzU5NTlaMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEo
# MCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBALtZnVlVT52Mcl0agaLrVfOwAa08cawy
# jwVrhponADKXak3JZBRLKbvC2Sm5Luxjs+HPPwtWkPhiG37rpgfi3n9ebUA41JEG
# 50F8eRzLy60bv9iVkfPw7mz4rZY5Ln/BJ7h4OcWEpe3tr4eOzo3HberSmLU6Hx45
# ncP0mqj0hOHE0XxxxgYptD/kgw0mw3sIPk35CrczSf/KO9T1sptL4YiZGvXA6TMU
# 1t/HgNuR7v68kldyd/TNqMz+CfWTN76ViGrF3PSxS9TO6AmRX7WEeTWKeKwZMo8j
# wTJBG1kOqT6xzPnWK++32OTVHW0ROpL2k8mc40juu1MO1DaXhnjFoTcCAwEAAaOC
# AXcwggFzMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMGYGA1Ud
# IARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5
# bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9y
# cGEwLgYIKwYBBQUHAQEEIjAgMB4GCCsGAQUFBzABhhJodHRwOi8vcy5zeW1jZC5j
# b20wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3Muc3ltY2IuY29tL3VuaXZlcnNh
# bC1yb290LmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAoBgNVHREEITAfpB0wGzEZ
# MBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMzAdBgNVHQ4EFgQUr2PWyqNOhXLgp7xB
# 8ymiOH+AdWIwHwYDVR0jBBgwFoAUtnf6aUhHn1MS1cLqBzJ2B9GXBxkwDQYJKoZI
# hvcNAQELBQADggEBAHXqsC3VNBlcMkX+DuHUT6Z4wW/X6t3cT/OhyIGI96ePFeZA
# Ka3mXfSi2VZkhHEwKt0eYRdmIFYGmBmNXXHy+Je8Cf0ckUfJ4uiNA/vMkC/WCmxO
# M+zWtJPITJBjSDlAIcTd1m6JmDy1mJfoqQa3CcmPU1dBkC/hHk1O3MoQeGxCbvC2
# xfhhXFL1TvZrjfdKer7zzf0D19n2A6gP41P3CnXsxnUuqmaFBJm3+AZX4cYO9uiv
# 2uybGB+queM6AL/OipTLAduexzi7D1Kr0eOUA2AKTaD+J20UMvw/l0Dhv5mJ2+Q5
# FL3a5NPD6itas5VYVQR9x5rsIwONhSrS/66pYYEwggVLMIIEM6ADAgECAhB71OWv
# uswHP6EBIwQiQU0SMA0GCSqGSIb3DQEBCwUAMHcxCzAJBgNVBAYTAlVTMR0wGwYD
# VQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1
# c3QgTmV0d29yazEoMCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGlu
# ZyBDQTAeFw0xNzEyMjMwMDAwMDBaFw0yOTAzMjIyMzU5NTlaMIGAMQswCQYDVQQG
# EwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5
# bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNIQTI1NiBU
# aW1lU3RhbXBpbmcgU2lnbmVyIC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQCvDoqq+Ny/aXtUF3FHCb2NPIH4dBV3Z5Cc/d5OAp5LdvblNj5l1SQg
# bTD53R2D6T8nSjNObRaK5I1AjSKqvqcLG9IHtjy1GiQo+BtyUT3ICYgmCDr5+kMj
# dUdwDLNfW48IHXJIV2VNrwI8QPf03TI4kz/lLKbzWSPLgN4TTfkQyaoKGGxVYVfR
# 8QIsxLWr8mwj0p8NDxlsrYViaf1OhcGKUjGrW9jJdFLjV2wiv1V/b8oGqz9KtyJ2
# ZezsNvKWlYEmLP27mKoBONOvJUCbCVPwKVeFWF7qhUhBIYfl3rTTJrJ7QFNYeY5S
# MQZNlANFxM48A+y3API6IsW0b+XvsIqbAgMBAAGjggHHMIIBwzAMBgNVHRMBAf8E
# AjAAMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0
# cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5
# bWNiLmNvbS9ycGEwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cDovL3RzLWNybC53cy5z
# eW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jcmwwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwDgYDVR0PAQH/BAQDAgeAMHcGCCsGAQUFBwEBBGswaTAqBggrBgEFBQcw
# AYYeaHR0cDovL3RzLW9jc3Aud3Muc3ltYW50ZWMuY29tMDsGCCsGAQUFBzAChi9o
# dHRwOi8vdHMtYWlhLndzLnN5bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNlcjAo
# BgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtNjAdBgNVHQ4E
# FgQUpRMBqZ+FzBtuFh5fOzGqeTYAex0wHwYDVR0jBBgwFoAUr2PWyqNOhXLgp7xB
# 8ymiOH+AdWIwDQYJKoZIhvcNAQELBQADggEBAEaer/C4ol+imUjPqCdLIc2yuaZy
# cGMv41UpezlGTud+ZQZYi7xXipINCNgQujYk+gp7+zvTYr9KlBXmgtuKVG3/KP5n
# z3E/5jMJ2aJZEPQeSv5lzN7Ua+NSKXUASiulzMub6KlN97QXWZJBw7c/hub2wH9E
# PEZcF1rjpDvVaSbVIX3hgGd+Yqy3Ti4VmuWcI69bEepxqUH5DXk4qaENz7Sx2j6a
# escixXTN30cJhsT8kSWyG5bphQjo3ep0YG5gpVZ6DchEWNzm+UgUnuW/3gC9d7GY
# FHIUJN/HESwfAD/DSxTGZxzMHgajkF9cVIs+4zNbgg/Ft4YCTnGf6WZFP3YxggJa
# MIICVgIBATCBizB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNV
# BAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEHvU5a+6zAc/oQEj
# BCJBTRIwCwYJYIZIAWUDBAIBoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAcBgkqhkiG9w0BCQUxDxcNMjQwMjA3MjI0NDExWjAvBgkqhkiG9w0BCQQxIgQg
# QA2hij3C2WOV/XSosew0NTdPI9RIVHPu0/ShPcOg+T4wNwYLKoZIhvcNAQkQAi8x
# KDAmMCQwIgQgxHTOdgB9AjlODaXk3nwUxoD54oIBPP72U+9dtx/fYfgwCwYJKoZI
# hvcNAQEBBIIBADCblIx0oxEnv0NFU3UpZAp2Dn5y2P2AtxYzGmhK6myh8OnSplv4
# Myq6VsBZIDxkn7nXxptVgyLLLVVzofe2CTPoxe4JFbQ6WhcPQk+eMJPHdMjIqfB8
# ER39OlUG8HnyBwfoWZF6Uggw80ByRtER9024WSGoncdua8AzGZ+ZnKsdzJfNPa9v
# Ii6jREmAfEWSaRbZBzwodGETrmtXddJrFQgGt7HtnI3fqklFqh1CKXhyhMrd+zTx
# hv4k/f6VNwS02LTayYQpgc+xeXTHMVVMgc4uzTkpjPpquDBgyqocp9wyCdt8qldx
# mA8oALnVQJXrT35+L7eswjsXxJMa31QUG80=
# SIG # End signature block
