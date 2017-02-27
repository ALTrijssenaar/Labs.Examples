Configuration CommonServer {
    param (
        [string]$ShareHostName,
        [PSCredential]$ShareCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xNetworking'
    Import-DscResource -ModuleName 'xRemoteDesktopAdmin'
    Import-DscResource -ModuleName 'CredentialManagement'

    # Administrator password never expires
    User Administrator {
        Ensure                 = 'Present'
        UserName               = 'Administrator'
        PasswordChangeRequired = $false
        PasswordNeverExpires   = $true
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
        Ensure                 = 'Present' 
        UserAuthentication     = 'Secure'
    }
    xFirewall AllowRDP {
        Ensure                 = 'Present'
        Name                   = 'RemoteDesktop-UserMode-In-TCP'
        Enabled                = 'True'
    }

    Registry DoNotOpenServerManagerAtLogon {
        Ensure                 = 'Present'
        Key                    = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
        ValueName              = 'DoNotOpenServerManagerAtLogon'
        ValueType              = 'Dword'
        ValueData              = 0x1
    }

	if ($ShareHostName -and $ShareCredential) {
        bManagedCredential ShareCredential {
            TargetName = $ShareHostName
            Ensure = 'Present'
            Credential = $ShareCredential
            CredentialType = 'DomainPassword'
            PersistanceScope ='LocalMachine'
        }
    }
}

Configuration DomainController {
    param (
        $Domain,
        [PSCredential]$DomainCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xComputerManagement'
    Import-DscResource -ModuleName 'xActiveDirectory'
    Import-DscResource -ModuleName 'xDnsServer'

    xComputer ComputerName {
        Name                           = $Node.Name
    }

    WindowsFeature ADDS {
        Name                           = 'AD-Domain-Services'
        DependsOn                      = '[xComputer]ComputerName'
    }
    WindowsFeature ADDSMgmtTools {
        Name                           = 'RSAT-ADDS-Tools'
        DependsOn                      = '[WindowsFeature]ADDS'
    }
    WindowsFeature DnsMgmtTools {
        Name                           = 'RSAT-DNS-Server'
        DependsOn                      = '[WindowsFeature]ADDS'
    }

    xADDomain ADDSForest { 
        DomainName                     = $Domain.Name
        DomainAdministratorCredential  = $DomainCredential
        SafemodeAdministratorPassword  = $DomainCredential
        DependsOn                      = "[WindowsFeature]ADDSMgmtTools"
    }

    # TODO: domain-users
    # TODO: DNS-aliases
}

Configuration MemberServer {
    param (
        $Domain,
        [PSCredential]$DomainCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xActiveDirectory'
    Import-DscResource -ModuleName 'xComputerManagement'

    xWaitForADDomain WaitForDomain {
        DomainName             = $Domain.Name
        DomainUserCredential   = $DomainCredential
        RetryIntervalSec       = 30
        RetryCount             = 480
    }
    xComputer ComputerNameAndDomain {
        Name                   = $Node.Name
        DomainName             = $Domain.Name
        Credential             = $DomainCredential
        DependsOn              = '[xWaitForADDomain]WaitForDomain'
    }
}

Configuration DhcpServer {
    param (
        $DhcpServer,
        $DnsServerIPAddress
    )

    Import-DscResource –ModuleName 'xDhcpServer'
    Import-DscResource –ModuleName 'bDhcpServer'

    WindowsFeature Dhcp {
        Name               = 'DHCP'
    }
    bDhcpServerConfigurationCompletion DhcpCompletion {
        Ensure             = 'Present'
        DependsOn          = '[WindowsFeature]Dhcp'
    }
    WindowsFeature DhcpMgmtTools {
        Name               = 'RSAT-DHCP'
        DependsOn          = '[WindowsFeature]Dhcp'
    }

    xDhcpServerAuthorization DhcpServerAuthorization {
        Ensure             = 'Present'
    }

    # NOTE: Binding not needed (?), binds to correct interface automatically
    #       Set-DhcpServerv4Binding -InterfaceAlias 'Internal' -BindingState $true

    xDhcpServerScope DhcpScope {
        Ensure             = 'Present'
        Name               = $DhcpServer.ScopeName
        IPStartRange       = $DhcpServer.StartRange
        IPEndRange         = $DhcpServer.EndRange
        SubnetMask         = $DhcpServer.SubnetMask
        LeaseDuration      = $DhcpServer.LeaseDurationDays
        State              = 'Active'
        DependsOn          = '[bDhcpServerConfigurationCompletion]DhcpCompletion'
    }
    xDhcpServerOption DhcpOptions {
        Ensure             = 'Present'
        ScopeID            = $DhcpServer.ScopeId
        DnsServerIPAddress = $DnsServerIPAddress
        Router             = $DhcpServer.DefaultGateway
        DependsOn          = '[xDhcpServerScope]DhcpScope'
    }

    # TODO: DHCP-reservations
}

Configuration ManagementServer {
    param (
        [string]$SharePath,
        [PSCredential]$ShareCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'

    WindowsFeature ADDSMgmtTools {
        Name                   = 'RSAT-ADDS-Tools'
    }
    WindowsFeature DnsMgmtTools {
        Name                   = 'RSAT-DNS-Server'
    }
    WindowsFeature DhcpMgmtTools {
        Name                   = 'RSAT-DHCP'
    }
}

Configuration DemoLabEnvironment {
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.NodeName {

        <# The following initialization is done in the setup-complete script
            + Initialize PowerShell environment (ExecutionPolicy:Unrestricted)
            + Enable PS-Remoting
            + Enable CredSSP
            + Format Extra-Disk (only if present and not yet formatted)
            + Configure DSC for Pull
        #>

        $domainNetwork = $Node.NetworkAdapters.Network |? { $_.Domain } | Select -First 1
        if ($domainNetwork) {
            $domain = $domainNetwork.Domain
            $domainCredential = New-Object -TypeName PSCredential -ArgumentList "$($domain.Name)\Administrator",(ConvertTo-SecureString -String $($domain.AdministratorPassword) -AsPlainText -Force)
        }

        if ($Node.Environment.Host -and
            $Node.Environment.Host.Share -and
            $Node.Environment.Host.Share.UserName -and
            $Node.Environment.Host.Share.Password) {

            $hostName = $Node.Environment.Host.Name
            $sharePath = "\\$($Node.Environment.Host.Name)\$($Node.Environment.Host.Share.Name)"
            if ($Node.Environment.Host.Share.Password -is [SecureString] ){
                $sharePassword = $Node.Environment.Host.Share.Password
            }
            else {
                $sharePassword = (ConvertTo-SecureString -String "$($Node.Environment.Host.Share.Password)" -AsPlainText -Force)
            }
            $shareCredential = New-Object -TypeName PSCredential -ArgumentList "$($Node.Environment.Host.Name)\$($Node.Environment.Host.Share.UserName)",$sharePassword
        }

        CommonServer CommonServer {
            ShareHostName = $hostName
            ShareCredential = $shareCredential
        }

        if ($Node.Role -contains ('DomainController')) {
            DomainController DomainController {
                Domain = $domain
                DomainCredential = $domainCredential
                DependsOn = '[CommonServer]CommonServer'
            }

            $dependsOn = @('[DomainController]DomainController')
            foreach ($networkAdapter in $Node.NetworkAdapters) {
                $network = $networkAdapter.Network
                if ($networkAdapter.StaticIPAddress -and $network.DhcpServer -and $networkAdapter.StaticIPAddress -eq $network.DhcpServer.IPAddress) {
                    $resourceName = "DhcpServer_$($network.Name)"
                    $dependsOn += "[DhcpServer]$resourceName"
                    DhcpServer $resourceName {
                        DhcpServer = $network.DhcpServer
                        DnsServerIPAddress = $network.DnsServer.IPAddress
                        DependsOn = '[DomainController]DomainController'
                    }
                }
            }

            Log Log_ServerBaseDone {
                Message = "Base configuration of '$($Node.Name)' finished"
                DependsOn = $dependsOn
            }
        }
        else {
            MemberServer MemberServer {
                Domain = $domain
                DomainCredential = $domainCredential
                DependsOn = '[CommonServer]CommonServer'
            }

            Log Log_ServerBaseDone {
                Message = "Base configuration of '$($Node.Name)' finished"
                DependsOn = '[MemberServer]MemberServer'
            }
        }

        $dependsOn = '[Log]Log_ServerBaseDone'
        foreach ($role in $Node.Role) {
            switch ($role) {
                'ManagementServer' {
                    ManagementServer ManagementServer {
                        SharePath = $sharePath
                        ShareCredential = $shareCredential
                        DependsOn = $dependsOn
                    }
                    $dependsOn = '[ManagementServer]ManagementServer'
                }
            }
        }
    }
}
