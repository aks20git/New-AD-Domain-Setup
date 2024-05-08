#Requires -Version 7.0

<#

.NOTES
  Version:        v1.0
  Author:         https://github.com/aks20git
  Creation Date:  May, 2024
  Purpose/Change: Using a JSON source file to set and reset ACL delegations for Users, Groups, and Computer objects

.Synopsis
Script requires a JSON source file for custom RBAC Active Directory OU delegation of Security attribute changes

.Description
A JSON file is used as a golden source to delegation permissions on the Product OUs for Users, Groups, and Computer objects

.Parameter JsonPath
This is a Mandatory parameter to the full path of the JSON delegation input file.

.Parameter Remove
This is an Mandatory parameter that should only be used when re-setting delegation
This is added as a function "Remove-OUDelegation". The PS1 file for this function must be placed in the same location

.Example
RBACOUDelegation.ps1 -JSONPath C:\Files\Delegation.json -Remove $false
Delegates the group ACLs to the OUs based on the JSON file as input

.Example
RBACOUDelegation.ps1 -JSONPath C:\Files\Delegation.json -Remove $true
Used only when delegations need to be removed and permissions reset

.Inputs
Requires a JSON file with specific objects for the script to execute properly

.Outputs
Regional Organizational Units will have the correct ACL's applied to manage Users, Groups, and Computer objects

.Note
Laps Commandlets require Powershell console to be 'Run As Admin'
#>


Param(
    [Parameter(Mandatory = $false)]
    [string]$JsonPath,

    [Parameter(Mandatory = $true)]
    [bool]$Remove
)

# Transcript Variables
$LogPath = "C:\Files\SetACL"
$LogDate = Get-Date -Format "yyyy-MM-dd_hh.mm.ss.ffftt"
$grpName = (Split-Path $JsonPath -Leaf).Split('.')[0]
$OutFile = "$LogPath\$grpName-$LogDate.txt"

Start-Transcript -Path $OutFile -NoClobber

# Import required modules
Import-Module ActiveDirectory -SkipEditionCheck -ErrorAction Stop
Import-Module "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdSchemaMap\AdGuidMap.psd1" -SkipEditionCheck -ErrorAction Stop
Import-Module LAPS -ErrorAction Stop
. "$LogPath\RemoveOUDelegation.ps1"

# Create Map Object GUID from the Schema for AD Delegation of objects scripts are not on GitHub but author can be found at https://github.com/constantinhager
$GuidMap = New-ADDGuidMap
$ExtendedRight = New-ADDExtendedRightMap

# Manual Testing JSON Input Path
#$JsonPath = "C:\Files\UserAdmins.json"

# Read the JSON content from the file
$jsonContent = Get-Content -Raw -Path $JsonPath | ConvertFrom-Json

# Process json content
$sitecodes = $jsonContent.OrganizationUnits[0].SiteCodes
$userDelegations = $jsonContent.Delegations[0].UserObjects
$groupDelegations = $jsonContent.Delegations[0].GroupObjects
$computerDelegations = $jsonContent.Delegations[0].ComputerObjects

# Add Generic Write Properties to an array
$genericWrites = @('ListChildren', `
                    'ReadProperty', `
                    'DeleteTree', `
                    'ExtendedRight', `
                    'Delete', `
                    'GenericWrite', `
                    'WriteOwner',
                    "CreateAllChild",
                    "DeleteAllChild"
                    )
#
#
#
#------------------------[User Object Delegations]------------------------#
#
#
#
if ($userDelegations.TargetOUs) {

    write-host ""
    Write-Host "#------------------------[User Object Delegations]------------------------#" -ForegroundColor Green
    write-host ""
    Start-Sleep 1

    # Begin User Object Loop --------#
    write-host ''
    write-host "Updating User Object Delegations.... " -ForegroundColor cyan
    Start-Sleep 1

    foreach ($sitecode in $sitecodes) {

        # Generate group name & get SID
        $ADGroup = "LD-"+$sitecode.productCode+"-$grpName"
        $ADGroupSID = (Get-ADGroup -Identity $ADGroup).SID

        # Loop through all user object locations
        foreach ($userDelegation in $userDelegations) {
            
            # Loop through all target OUs
            foreach ($targetOU in $userDelegation.TargetOUs) {

                # Generate target OU location
                $OUpath = "OU="+$targetOU+",OU=Management,"+$sitecode.productDN
                $ADOU = ("AD:\" + $OUpath)
                $UserACE = Get-ACL -Path $ADOU

                # Remove the Task Groups from the OU if Remove is specified
                if ($Remove) {
                    write-host "Purging Existing Delegations.... " -ForegroundColor Magenta
                    Start-Sleep 1

                    Remove-OUDelegation -ADGroupSID $ADGroupSID -ADOU $ADOU -ADGroup $ADGroup -RemoveACL $UserACE
                }

                # Loop thorugh all permissions
                foreach ($property in $userDelegation.Permissions) {

                    # Process Create & Delete Permissions for User Objects --------#
                    if (($property -eq "CreateChild") -or ($property -eq "DeleteChild")) {

                        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                    
                        # Create the Active Directory access rule for Create & Delete----#
                        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $permissionSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::$property,
                        [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["User"],
                        [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
                        )
                    
                        Write-Host "[+] Delegating $($property) 'User Objects' to $($ADGroup) on $($ADOU)" -f gray
                
                        # Add the rule to the ACL
                        $UserACE.AddAccessRule($permissionRule)
                        Set-Acl -Path $ADOU -AclObject $UserACE
                    }
                    
                    # Process Change/Reset Password Permissions for User Objects --------#
                    elseif (($property -eq "Change Password") -or ($property -eq "Reset Password")) {
                            
                        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                        
                        # Create the Active Directory access rule for password permissions----#
                        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $permissionSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                        [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$property],
                        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
                        )
                
                        write-host "[+] Delegating WriteProperty to $($ADGroup) on $($ADOU) for attribute $($property) " -f gray
                        # Add the rule to the ACL
                        $UserACE.AddAccessRule($permissionRule)
                        Set-ACL -Path $ADOU -AclObject $UserACE
                    }

                    # Set Permissions for Generic Write
                    elseif ($property -in $genericWrites) {
                        
                        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                
                        # Create the Active Directory access rule for the property----#
                        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $permissionSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
                        )
                
                        write-host "[+] Delegating WriteProperty to $($ADGroup) on $($ADOU) for attribute $($Property) " -f gray
                        # Add the rule to the ACL
                        $UserACE.AddAccessRule($permissionRule)
                        Set-ACL -Path $ADOU -AclObject $UserACE
                    }

                    # Set other attribute permissions
                    else {
                        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                    
                            # Create the Active Directory access rule for the property----#
                            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $permissionSID,
                            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$Property],
                            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
                            )

                        write-host "[+] Delegating WriteProperty to $($ADGroup) on $($ADOU) for attribute $($Property) " -f gray
                        # Add the rule to the ACL
                        $UserACE.AddAccessRule($permissionRule)
                        Set-ACL -Path $ADOU -AclObject $UserACE

                    }
                }
            }
        }
    }
}

#
#
#
#------------------------[Group Object Delegations]------------------------#
#
#
#
if ($groupDelegations.TargetOUs) {

    write-host ""
    Write-Host "#------------------------[Group Object Delegations]------------------------#" -ForegroundColor Green
    write-host ""
    Start-Sleep 1

    # Begin Group Object Loop --------#
    write-host ''
    write-host "Writing New Delegations.... " -ForegroundColor cyan
    Start-Sleep 1

    foreach ($sitecode in $sitecodes) {

        # Generate group name & get SID
        $ADGroup = "LD-"+$sitecode.productCode+"-$grpName"
        $ADGroupSID = (Get-ADGroup -Identity $ADGroup).SID

        # Loop through all group object locations
        foreach ($groupDelegation in $groupDelegations) {
            
            # Loop through all target OUs
            foreach ($targetOU in $groupDelegation.TargetOUs) {

                # Generate target OU location
                $OUpath = "OU="+$targetOU+",OU=Management,"+$sitecode.productDN
                $ADOU = ("AD:\" + $OUpath)
                $GroupACE = Get-ACL -Path $ADOU

                # Remove the Task Groups from the OU if Remove is specified
                if ($Remove) {
                    write-host "Purging Existing Delegations.... " -ForegroundColor Magenta
                    Start-Sleep 1

                    Remove-OUDelegation -ADGroupSID $ADGroupSID -ADOU $ADOU -ADGroup $ADGroup -RemoveACL $GroupACE
                }

                # Loop thorugh all permissions
                foreach ($property in $groupDelegation.Permissions) {

                    # Process Create & Delete Permissions for Group Objects --------#
                    if (($property -eq "CreateChild") -or ($property -eq "DeleteChild")) {

                        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                    
                        # Create the Active Directory access rule for Create & Delete----#
                        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $permissionSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::$property,
                        [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["Group"],
                        [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
                        )
                    
                        Write-Host "[+] Delegating $($property) 'Group Objects' to $($ADGroup) on $($ADOU)" -f gray
                
                        # Add the rule to the ACL
                        $GroupACE.AddAccessRule($permissionRule)
                        Set-Acl -Path $ADOU -AclObject $GroupACE
                    }

                    # Set Permissions for Generic Write
                    elseif ($property -in $genericWrites) {
                        
                        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                
                        # Create the Active Directory access rule for the property----#
                        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $permissionSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["Group"]
                        )
                
                        write-host "[+] Delegating $($property) 'Group Objects' to $($ADGroup) on $($ADOU)" -f gray

                        # Add the rule to the ACL
                        $GroupACE.AddAccessRule($permissionRule)
                        Set-ACL -Path $ADOU -AclObject $GroupACE
                    }

                    # Set other attribute permissions
                    else {
                        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                    
                            # Create the Active Directory access rule for the property----#
                            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $permissionSID,
                            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$Property],
                            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["Group"]
                            )

                        write-host "[+] Delegating $($property) 'Group Objects' to $($ADGroup) on $($ADOU)" -f gray

                        # Add the rule to the ACL
                        $GroupACE.AddAccessRule($permissionRule)
                        Set-ACL -Path $ADOU -AclObject $GroupACE

                    }
                }
            }
        }
    }
}
#
#
#
#------------------------[Computer Object Delegations]------------------------#
#
#
#
if ($computerDelegations.TargetOUs) {

    write-host ""
    Write-Host "#------------------------[Computer Object Delegations]------------------------#" -ForegroundColor Green
    write-host ""
    Start-Sleep 1

    # Begin Computer Object Loop --------#
    write-host ''
    write-host "Writing New Delegations.... " -ForegroundColor cyan
    Start-Sleep 1

    foreach ($sitecode in $sitecodes) {

        # Loop through each site based Computer OUs
        foreach ($site in $sitecode.Sites) {

            # Generate group name & get SID
            $ADGroup = "LD-"+$site+"-$grpName"
            $ADGroupSID = (Get-ADGroup -Identity $ADGroup).SID

            # Loop through all Computer object locations
            foreach ($computerDelegation in $computerDelegations) {
            
                # Loop through all target OUs
                foreach ($targetOU in $computerDelegation.TargetOUs) {
                    
                    # Remove CEM and GFC from the OU path location
                    if (($site -eq "WET-CEM") -or ($site -eq "WET-GFC")) {
                        $site = "WET"
                    }

                    # Generate target OU location
                    $OUpath = "OU="+$targetOU+",OU=$site,"+$sitecode.productDN
                    $ADOU = ("AD:\" + $OUpath)
                    $ComputerACE = Get-ACL -Path $ADOU

                    # Remove the Task Groups from the OU if Remove is specified
                    if ($Remove) {
                        write-host "Purging Existing Delegations.... " -ForegroundColor Magenta
                        Start-Sleep 1

                        Remove-OUDelegation -ADGroupSID $ADGroupSID -ADOU $ADOU -ADGroup $ADGroup -RemoveACL $ComputerACE
                    }

                    # Loop thorugh all permissions
                    foreach ($property in $computerDelegation.Permissions) {

                        # Process Create & Delete Permissions for Computer Objects --------#
                        if (($property -eq "CreateChild") -or ($property -eq "DeleteChild")) {

                            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                        
                            # Create the Active Directory access rule for Create & Delete----#
                            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $permissionSID,
                            [System.DirectoryServices.ActiveDirectoryRights]::$property,
                            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["Computer"],
                            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
                            )
                        
                            Write-Host "[+] Delegating $($property) 'Computer Objects' to $($ADGroup) on $($ADOU)" -f gray
                    
                            # Add the rule to the ACL
                            $ComputerACE.AddAccessRule($permissionRule)
                            Set-Acl -Path $ADOU -AclObject $ComputerACE
                        }

                        # Set Permissions for Generic Write
                        elseif ($property -in $genericWrites) {

                            # For Create/Delete All Child Rights
                            if ($property -eq "CreateAllChild") {
                                $property = "CreateChild"
                            }
                            elseif ($property -eq "DeleteAllChild") {
                                $property = "DeleteChild"
                            }
                            
                            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                    
                            # Create the Active Directory access rule for the property----#
                            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $permissionSID,
                            [System.DirectoryServices.ActiveDirectoryRights]::$Property,
                            [System.Security.AccessControl.AccessControlType]::Allow,
                            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["Computer"]
                            )
                    
                            write-host "[+] Delegating $($property) 'Computer Objects' to $($ADGroup) on $($ADOU)" -f gray

                            # Add the rule to the ACL
                            $ComputerACE.AddAccessRule($permissionRule)
                            Set-ACL -Path $ADOU -AclObject $ComputerACE
                        }

                        # Set Read LAPS permissions
                        elseif ($property -eq "LAPSRead") {

                            write-host "[+] Delegating $($property) 'Computer Objects' to $($ADGroup) on $($ADOU)" -f gray

                            # Sets the read LAPS permission on the Computer Objects
                            Set-LapsADReadPasswordPermission -Identity $OUpath -AllowedPrincipals $ADGroupSID
                        }

                        # Set Write LAPS permissions
                        elseif ($property -eq "LAPSWrite") {

                            write-host "[+] Delegating $($property) 'Computer Objects' to $($ADGroup) on $($ADOU)" -f gray

                            # Sets the read LAPS permission on the Computer Objects
                            Set-LapsADReadPasswordPermission -Identity $OUpath -AllowedPrincipals $ADGroupSID

                            # Sets the Set LAPS permission on the Computer Objects
                            Set-LapsADResetPasswordPermission -Identity $OUpath -AllowedPrincipals $ADGroupSID
                        }

                        # Set other attribute permissions
                        else {
                            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
                        
                                # Create the Active Directory access rule for the property----#
                                $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $permissionSID,
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$Property],
                                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["Computer"]
                                )

                            write-host "[+] Delegating $($property) 'Computer Objects' to $($ADGroup) on $($ADOU)" -f gray

                            # Add the rule to the ACL
                            $ComputerACE.AddAccessRule($permissionRule)
                            Set-ACL -Path $ADOU -AclObject $ComputerACE

                        }
                    }
                }
            }
        }
    }
}
Stop-Transcript