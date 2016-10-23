
#######################################
# Load configuration
#######################################
Write-Log "INFO" "Loading configuration"
$configuration = Get-content -Path "$setupFolder\configuration.json" -Raw | ConvertFrom-Json
Write-Log "INFO" "Finished loading configuration"

#######################################
# Apply configuration
#######################################
$configurationFilePath = "$setupFolder\LabEnvironment.ps1"
if (Test-Path -Path $configurationFilePath) {
    Write-Log "INFO" "Start applying configuration"
    Write-Log "INFO" "Preparing configuration for DSC"
    $configuration `
        | Add-Member -MemberType NoteProperty -Name NodeName -Value 'localhost' -PassThru `
        | Add-Member -MemberType NoteProperty -Name PSDscAllowPlainTextPassword -Value $true `
        | Add-Member -MemberType NoteProperty -Name PSDscAllowDomainUser -Value $true

    $configurationData = @{
        AllNodes = @(
            (Convert-PSObjectToHashtable $configuration)
        )
    }
    Write-Log "INFO" "Loading configuration"
    . "$setupFolder\LabEnvironment.ps1"
    Write-Log "INFO" "Generating configuration"
    LabConfiguration -ConfigurationData $configurationData -OutputPath "$setupFolder\LabEnvironment" | Out-Null
    Write-Log "INFO" "Starting configuration"
    Start-DscConfiguration –Path $setupFolder\LabEnvironment –Wait -Force –Verbose | Out-Null
    Write-Log "INFO" "Finished applying configuration"
}
else {
    Write-Log "INFO" "Skipping configuration"
}
