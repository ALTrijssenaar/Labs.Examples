
#######################################
# Update LocalConfigurationManager
#######################################
Write-Log "INFO" "Updating LocalConfigurationManager with RebootNodeIfNeeded"
configuration LCM_RebootNodeIfNeeded {
    node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }
    }
}

#######################################
# Load configuration
#######################################
Write-Log "INFO" "Loading configuration"
$configuration = Get-content -Path "$setupFolder\configuration.json" -Raw | ConvertFrom-Json
Write-Log "INFO" "Finished loading configuration"

#######################################
# Apply configuration
#######################################
$configurationFilePath = "$setupFolder\DscConfiguration.ps1"
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
    . $configurationFilePath
    Write-Log "INFO" "Generating configuration"
    $outputPath = Join-Path -Path $PSScriptRoot -ChildPath ([System.IO.Path]::GetFileNameWithoutExtension($configurationFilePath))
    DemoLabEnvironment -ConfigurationData $configurationData -OutputPath $outputPath | Out-Null
    Write-Log "INFO" "Starting configuration"
    Start-DscConfiguration –Path $outputPath –Wait -Force –Verbose | Out-Null
    Write-Log "INFO" "Finished applying configuration"
}
else {
    Write-Log "INFO" "Skipping configuration"
}
