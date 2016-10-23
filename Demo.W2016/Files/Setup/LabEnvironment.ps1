
Configuration CommonServer {

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xNetworking'
    Import-DscResource -ModuleName 'xRemoteDesktopAdmin'

    # Administrator password never expires
    User Administrator {
        Ensure                  = 'Present'
        UserName                = 'Administrator'
        PasswordChangeRequired  = $false
        PasswordNeverExpires    = $true
    }

    foreach ($networkAdapter in $Node.NetworkAdapters) {
        $netAdapter = $null

        $nameProperty = Get-NetAdapterAdvancedProperty -Name * |? { $_.ValueName -eq 'HyperVNetworkAdapterName' -and $_.DisplayValue -eq $networkAdapter.Network.Name } | select -First 1
        if ($nameProperty) {
            $netAdapter = Get-NetAdapter |? { $_.Name -eq $nameProperty.InterfaceAlias }
            if (-not $netAdapter) {
                Log "Log_NetworkAdapter_$($networkAdapter.Network.Name)_Alias_Failure" {
                    Message = "WARNING: Unable to find network-adapter for alias '$($nameProperty.InterfaceAlias)'"
                }
            }
        }
        else {
            Log "Log_NetworkAdapter_$($networkAdapter.Network.Name)_Property_Failure" {
                Message = "WARNING: Unable to find network-adapter property for name '$($networkAdapter.Network.Name)'"
            }
        }

        if (-not $netAdapter -and $networkAdapter.StaticMacAddress) {
            $netAdapter = Get-NetAdapter |? { $_.MacAddress -eq $networkAdapter.StaticMacAddress }
        }

        if (-not $netAdapter) {
            Log "Log_NetworkAdapter_$($networkAdapter.Network.Name)_Failure" {
                Message = "WARNING: Unable to find network-adapter for '$($networkAdapter.Network.Name)'"
            }

            continue
        }

        if ($networkAdapter.StaticIPAddress) {
            <# NOTE: xDhcpClient not yet available; but setting static IP address will disable DHCP
            xDhcpClient EnableDhcpClient
            {
                InterfaceAlias      = $netAdapter.Name
                AddressFamily       = $networkAdapter.AddressFamily
                State               = 'Enabled'
            }#>

            xIPAddress "Network_$($netAdapter.Name)" {
                InterfaceAlias      = $netAdapter.Name
                AddressFamily       = $networkAdapter.Network.AddressFamily
                IPAddress           = $networkAdapter.StaticIPAddress
                SubnetMask          = $networkAdapter.Network.PrefixLength
            }

            if ($networkAdapter.Network.Domain -and $networkAdapter.Network.Domain.DnsServerIPAddress) {
                xDnsServerAddress "DnsServerAddress_$($netAdapter.Name)" {
                    InterfaceAlias = $netAdapter.Name
                    AddressFamily  = $networkAdapter.Network.AddressFamily
                    Address        = $networkAdapter.Network.Domain.DnsServerIPAddress
                    DependsOn      = "[xIPAddress]Network_$($netAdapter.Name)"
                }
            }
        }
        else {
            <# NOTE: xDhcpClient not yet available; but network-adapters have DHCP enable by default
            xDhcpClient DisableDhcpClient
            {
                InterfaceAlias     = $netAdapter.Name
                AddressFamily      = $networkAdapter.AddressFamily
                State              = 'Disabled'
            }#>
        }
    }

    xRemoteDesktopAdmin RemoteDesktopSettings {
        Ensure					= 'Present' 
        UserAuthentication		= 'Secure'
    }
    xFirewall AllowRDP {
        Ensure					= 'Present'
        Name					= 'RemoteDesktop-UserMode-In-TCP'
        Enabled					= 'True'
    }

    Registry DoNotOpenServerManagerAtLogon {
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
        ValueName = 'DoNotOpenServerManagerAtLogon'
        ValueType = 'Dword'
        ValueData = 0x1
    }
}

Configuration LabConfiguration {

    Node $AllNodes.NodeName {

        <# The following initialization is done in the setup-complete script
            + Initialize PowerShell environment (ExecutionPolicy:Unrestricted)
            + Enable PS-Remoting
            + Enable CredSSP
            + Format Extra-Disk (only if present and not yet formatted)
            + Change LCM:RebootNodeIfNeeded
            + Execute SetupScript.ps1, which applies this configuration
        #>

        CommonServer CommonServer { }
    }
}
