function Remove-OUDelegation {
    Param(
        [Parameter(Mandatory = $True)]
	    [String]$ADGroupSID,

        [Parameter(Mandatory = $True)]
	    [String]$ADOU,

        [Parameter(Mandatory = $True)]
	    [String]$ADGroup,

        [Parameter(Mandatory = $True)]
        $RemoveACL
    )
    
    # Loop Task Group Delegation Removal
    $removeAce = New-Object System.Security.Principal.SecurityIdentifier $ADGroupSID
    $RemoveACL.PurgeAccessRules($removeAce)

    Write-Host "[+]Removing $($ADGroup) from $($ADOU)" -ForegroundColor Yellow
    Set-Acl -Path $ADOU -AclObject $RemoveACL
}