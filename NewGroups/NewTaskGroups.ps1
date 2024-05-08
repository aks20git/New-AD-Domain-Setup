<#
.NOTES
  Version:        v1.0
  Author:         https://github.com/aks20git
  Creation Date:  April, 2024
  Purpose/Change: Using a JSON source file to create task based groups

.Synopsis
Script requires a JSON source file for group location and names

.Description
A JSON file is used as a golden source with OU path, names & description of the new groups to be created

.Parameter JsonPath
This is a Mandatory parameter to the full path of the JSON delegation input file

.Example
NewOUStructure -JsonFile C:\Files\NewTaskGroups.json
Creating new task groups for site based delegation

.Inputs
Requires a JSON file with DN for the script to execute properly

.Outputs
Task groups will be created for each of the sites and the transaction logged. The output file path needs to be set
#>

Param(
    [Parameter(Mandatory = $false)]
    [string]$JsonPath
)

# Transcript Variables
$LogDate = Get-Date -Format "yyyy-MM-dd_hh.mmtt"
$OutFile = "C:\Files\NewGroups\$LogDate.txt"

Start-Transcript -Path $OutFile -NoClobber

# Import required modules
Import-Module ActiveDirectory

# Manual Testing JSON Input Path
#$JsonPath = "C:\Files\NewGroups\NewTaskGroups.json"

# Read the JSON content from the file
$jsonContent = Get-Content -Raw -Path $JsonPath | ConvertFrom-Json

# Process json content
$productsOUDN = $jsonContent.OrganizationUnits[0].SiteCodes
$productgroups = $jsonContent.Groups[0].ProductGroups
$sitegroups = $jsonContent.Groups[0].SiteGroups

# Loop each product and get sites
foreach ($product in $productsOUDN) {

    # Add Task Group OU Path
    $taskgrpOU = "OU=Task Groups,OU=Management,"+$product.productDN
    $siteCodes = $product.Sites

    # Create Product product based task groups
    foreach ($productgroup in $productgroups) {

        # Generate product group names
        $grpName = "LD-" + $product.productCode + "-" + $productgroup.Name
        $grpDesc = $productgroup.Description + " $product.productCode Sites"

        try {
            # Create task groups in the products OU
            Write-Host "Creating group $grpName under $taskgrpOU" -ForegroundColor Blue           
            New-ADGroup -Name $grpName -Description $grpDesc -GroupScope DomainLocal -Path $taskgrpOU
        }
        catch {
            Write-Host "$grpName already exists" -ForegroundColor Green
        }
    }

    # Create site based task groups
    foreach ($siteCode in $siteCodes) {

        # Create Product product based task groups
        foreach ($sitegroup in $sitegroups) {

            # Generate sites based task groups
            $grpName = "LD-$siteCode-"+$sitegroup.Name
            $grpDesc = $sitegroup.Description + " $siteCode Site"
            
            try {
                # Create task groups in the products OU
                Write-Host "Creating group $grpName under $taskgrpOU" -ForegroundColor Cyan           
                New-ADGroup -Name $grpName -Description $grpDesc -GroupScope DomainLocal -Path $taskgrpOU
            }
            catch {
                Write-Host "$grpName already exists" -ForegroundColor Green
            }
        }
    }
}
Stop-Transcript