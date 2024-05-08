<#
.NOTES
  Version:        v1.0
  Author:         https://github.com/aks20git
  Creation Date:  April, 2024
  Purpose/Change: Using a JSON source file to create OU Structure in AD

.Synopsis
Script requires a JSON source file for OU names and locations

.Description
A JSON file is used as a golden source with path and names of the new OUs to be created

.Parameter JsonPath
This is a Mandatory parameter to the full path of the JSON delegation input file

.Example
NewOUStructure -JsonFile C:\Files\OUStructure.json
Creating new OU Structure

.Inputs
Requires a JSON file with DN for the script to execute properly

.Outputs
Task groups will be created for each of the sites and the transaction logged. The output file path needs to be set
#>

Param(
    [Parameter(Mandatory = $false)]
    [string]$JsonPath,

    [Parameter(Mandatory = $true)]
    [bool]$brandsOU,

    [Parameter(Mandatory = $true)]
    [bool]$sitesOU
)

Import-Module ActiveDirectory

# Manual Testing JSON Input Path
#$JsonPath = ".\OUStructure.json"

# Read the JSON content from the file
$jsonContent = Get-Content -Raw -Path $JsonPath | ConvertFrom-Json

# Process json content
$brands = $jsonContent.OrganizationUnits[0].Brands
$sites = $jsonContent.OrganizationUnits[0].Sites
$siteSubOUs = $jsonContent.OrganizationUnits[0].SiteSubOUs
$brandSubOUs = $jsonContent.OrganizationUnits[0].BrandSubOUs

if ($brandsOU) {
    # Create Sub-OUs under Sites
    foreach ($brand in $brands) {

        # Add Management OU to the DN
        $brandOUDN = "OU=Management,"+$brand.DN
        $brandADcode = $brand.Code

        #Create Child OUs
        foreach ($brandSubOU in $brandSubOUs) {
            Write-Host "Creating $brandSubOU OU under $brandADcode" -ForegroundColor Yellow
            New-ADOrganizationalUnit -Name $brandSubOU -Path $brandOUDN -ProtectedFromAccidentalDeletion $true
        }
    }
}
elseif ($sitesOU) {
    # Create Sub-OUs under Sites
    foreach ($site in $sites) {
        $siteOUDN = $site.DN
        $siteADcode = $site.Code

        #Create Child OUs
        foreach ($SiteSubOU in $SiteSubOUs) {
            Write-Host "Creating $SiteSubOU OU under $siteADcode" -ForegroundColor Yellow
            New-ADOrganizationalUnit -Name $SiteSubOU -Path $siteOUDN -ProtectedFromAccidentalDeletion $true
        }
    }
}