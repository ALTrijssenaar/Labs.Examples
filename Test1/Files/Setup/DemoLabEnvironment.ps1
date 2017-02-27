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
        $network = $networkAdapter.Network
        if ($networkAdapter.StaticIPAddress) {
            xDhcpClient "DisableDHCP_$($network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                State              = 'Disabled'
            }

            xIPAddress "Network_$($networkAdapter.Network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                IPAddress          = $networkAdapter.StaticIPAddress
                SubnetMask         = $network.PrefixLength
                DependsOn          = "[xDhcpClient]DisableDHCP_$($network.Name)"
            }

            if ($network.DnsServer -and $network.DnsServer.IPAddress) {
                xDnsServerAddress "DnsServerAddress_$($networkAdapter.Network.Name)" {
                    InterfaceAlias = $network.Name
                    AddressFamily  = $network.AddressFamily
                    Address        = $network.DnsServer.IPAddress
                    DependsOn      = "[xIPAddress]Network_$($network.Name)"
                }
            }

            if ($networkAdapter.DefaultGateway) {
                xDefaultGatewayAddress "xDefaultGatewayAddress_$($networkAdapter.Network.Name)" {
                    InterfaceAlias = $network.Name
                    AddressFamily  = $network.AddressFamily
                    Address        = $networkAdapter.DefaultGateway
                    DependsOn      = "[xIPAddress]Network_$($network.Name)"
                }
            }
        }
        else {
            xDhcpClient "EnableDHCP_$($network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                State              = 'Enabled'
            }
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

Configuration DemoLabEnvironment {

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
