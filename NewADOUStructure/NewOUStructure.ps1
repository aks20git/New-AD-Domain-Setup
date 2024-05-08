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