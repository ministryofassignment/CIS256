#CIS256-Exam_Final_Practical.test.ps1 written by Kevin Azevedo on 4/28/2020
#A script to grade the CIS256 Final Practical Exam
BeforeAll {
    $secpassword = ConvertTo-SecureString Password1 -AsPlainText -Force
    $ServerCredential = New-Object System.Management.Automation.PSCredential("medical-emr\Administrator",$secpassword)
    $Server1Session = New-PSSession -VMName CIS256-FP-DC1 -Credential $ServerCredential
    $ClientSession = New-PSSession -VMName CIS256-FP-Client -Credential $ServerCredential
    $domain = Invoke-Command -Session $Server1Session -ScriptBlock { Get-ADDomain }
    $line = "=" * 66
    Write-Host -ForegroundColor Green "`t`t`tCIS256 Final Practical"
    Write-Host "`t`t`t" (hostname) -ForegroundColor Cyan
    Write-Host "`t`t" (Get-WMIObject -Class Win32_computerSystemProduct).UUID -Foreground Cyan
    Write-Host "`t`t" (Get-Date).DateTime -ForegroundColor Cyan
}
Describe "CIS256 Final Practical Exam" {
    Context "CIS256-FP-DC1 Configuration" -Tag SVR {
        BeforeAll {
                $IPSettings = @{
			        "LAN" = @{
				        "IPAddress" = "10.199.152.1"
				        "PrefixLength" = "24"
                        "DNSServer" = "127.0.0.1"
                        "Gateway" = "10.199.152.254"
		                "Name" = "MEDC1"
                        }
                }
                $ipconfig = Invoke-Command -Session $Server1Session -ScriptBlock { Get-NetAdapter | Get-NetIPAddress -AddressFamily IPv4 }
                $route = Invoke-Command -Session $Server1Session -ScriptBlock { Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0}
                $hostname = Invoke-Command -Session $Server1Session -ScriptBlock { hostname }
                $dnsserver = Invoke-Command -Session $Server1Session -ScriptBlock { Get-NetAdapter | Get-DnsClientServerAddress -AddressFamily IPv4 }
                $roles = Invoke-Command -Session $Server1Session -ScriptBlock { Get-WindowsFeature }
        }
        Context "Network Configuration" {
            It "IP Address configured correctly"  {
                Write-host "`nVerifying NIC (5 points) " (Get-Date).Ticks -ForegroundColor Cyan
                Write-Host $line -ForegroundColor DarkGreen
                $ipconfig.ipaddress | Should -Be ($IPSettings.LAN.IPAddress)
            }
            It "Default Gateway configured correctly"  {
                $route.NextHop | Should -Be ($IPSettings.LAN.Gateway)
            }
            It "DNS Server configured correctly" {
                $dnsserver.serverAddresses | Should -Contain ($IPSettings.LAN.DNSServer)
            }
             It "Computer name configured correctly" {
                Write-host "Verifying Server Name (5 points) " (Get-Date).Ticks -ForegroundColor Cyan
                Write-Host $line -ForegroundColor DarkGreen
                $hostname | Should -Be ($IPSettings.LAN.Name)
            }
        }
        Context "Active Directory Configuration" {
            It "Active Directory Domain Services installed" {
                Write-host "Verifying AD Installation (10 points) " (Get-Date).Ticks -ForegroundColor Cyan
                Write-Host $line -ForegroundColor DarkGreen
                $role = $roles | ? Name -EQ "AD-Domain-Services"
                $role.installState | Should -Be "Installed"
            }
            It "Promoted to Domain Controller" {
                $domain.dnsroot | Should -be "medical-emr.com"
            }
        }
    }


    Context "Active Directory Configuration" -Tag AD {
        BeforeAll {
            $actOUs = Invoke-Command -Session $Server1Session -ScriptBlock { Get-ADOrganizationalUnit -Filter *}
            $OUs = (
                        "OU=Pickens,DC=Medical-emr,DC=com",
                        "OU=IT,OU=Pickens,DC=Medical-emr,DC=com",
                        "OU=Medical,OU=Pickens,DC=Medical-emr,DC=com",
                        "OU=Greenville,DC=Medical-emr,DC=com",
                        "OU=IT,OU=Greenville,DC=Medical-emr,DC=com",
                        "OU=Medical,OU=Greenville,DC=Medical-emr,DC=com")
            $groups = @{
			    "Greenville-IT" = @{
				    "DistinguishedName" = "CN=Greenville-IT,OU=Greenville,DC=Medical-emr,DC=com"
				    "GroupScope" = "Global"
                    "Members" = 30
		            }
			    "Greenville-Medical" = @{
				    "DistinguishedName" = "CN=Greenville-Medical,OU=Greenville,DC=Medical-emr,DC=com"
				    "GroupScope" = "Global"
                    "Members" = 211
		            }
			    "Greenville" = @{
				    "DistinguishedName" = "CN=Greenville,OU=Greenville,DC=Medical-emr,DC=com"
				    "GroupScope" = "Global"
                    "Members" = "CN=Greenville-IT,OU=Greenville,DC=Medical-emr,DC=com","CN=Greenville-Medical,OU=Greenville,DC=Medical-emr,DC=com"
		            }
                "Pickens-IT" = @{
				    "DistinguishedName" = "CN=Pickens-IT,OU=Pickens,DC=Medical-emr,DC=com"
				    "GroupScope" = "Global"
                    "Members" = 28
		            }
                "Pickens-Medical" = @{
				    "DistinguishedName" = "CN=Pickens-Medical,OU=Pickens,DC=Medical-emr,DC=com"
				    "GroupScope" = "Global"
                    "Members" = 200
		            }
                "Pickens" = @{
				    "DistinguishedName" = "CN=Pickens,OU=Pickens,DC=Medical-emr,DC=com"
				    "GroupScope" = "Global"
                    "Members" = "CN=Pickens-IT,OU=Pickens,DC=Medical-emr,DC=com","CN=Pickens-Medical,OU=Pickens,DC=Medical-emr,DC=com"
		            }
                "MEDC1-Medapps-R" = @{
		    		"DistinguishedName" = "CN=MEDC1-Medapps-R,CN=Users,DC=medical-emr,DC=com"
			    	"GroupScope" = "DomainLocal"
                    "Members" = "CN=medical-emr,CN=Users,DC=medical-emr,DC=com"
		            }
                "MEDC1-Medapps-FC" = @{
		    		"DistinguishedName" = "CN=MEDC1-Medapps-FC,CN=Users,DC=medical-emr,DC=com"
			    	"GroupScope" = "DomainLocal"
                    "Members" = "CN=Greenville-IT,OU=Greenville,DC=medical-emr,DC=com"
		            }

			    "medical-emr" = @{
				    "DistinguishedName" = "CN=medical-emr,CN=Users,DC=medical-emr,DC=com"
				    "GroupScope" = "Global"
                    "Members" = "CN=Greenville,OU=Greenville,DC=Medical-emr,DC=com","CN=Pickens,OU=Pickens,DC=Medical-emr,DC=com"
		            }
            }
        }
        Context "Organizational Unit Creation" {
            IT "Verify OU creation" {
                Write-host "Verifying OU Creation (10 points) " (Get-Date).Ticks -ForegroundColor Cyan
                Write-Host $line -ForegroundColor DarkGreen
            }
            It "OUs created" {               
                foreach ($ou in $OUs) {
                    $ou | Should -BeIn ($actOUs.DistinguishedName)
                }
            }
        }

        Context "Users placed in the correct groups" {
            IT "Verify user Import" {
                Write-host "Verifying Users Imported (10 points) " (Get-Date).Ticks -ForegroundColor Cyan
                Write-Host $line -ForegroundColor DarkGreen
            }
            It "Group membership is correct" {
                foreach ($group in $groups.Keys) {
                    $groupInfo = Invoke-Command -Session $Server1Session -ScriptBlock { Get-ADGroupMember -Identity $Using:group | Sort-Object }
                    if ($groups.$group.Members -is [int]) {
                        $groupInfo.count | Should -be ($groups.$group.Members)
                    }else{
                        $groupInfo.distinguishedName | Should -be ($groups.$group.Members)
                    }
                }
            }
        }
        Context "Group Creation" {
            It "Groups created and configured correctly" {
                Write-host "Verifying Groups Created (15 points) " (Get-Date).Ticks -ForegroundColor Cyan
                Write-Host $line -ForegroundColor DarkGreen
                
                foreach ($group in $groups.Keys) {
                    $groupInfo = Invoke-Command -Session $Server1Session -ScriptBlock { Get-ADGroup -Identity $Using:group }
                    $groupInfo | Should -Not -BeNullOrEmpty
                    $groupInfo.Distinguishedname | Should -be ($groups.$group.DistinguishedName)
                    $groupInfo.GroupScope | Should -be ($groups.$group.GroupScope)
                }
            }
        }

        

        Context "Group Policy Configuration" {
            BeforeAll {
                [xml]$gpfile1 = Invoke-Command -Session $Server1Session -ScriptBlock {Get-GPOReport -Name "Application Allow List" -ReportType XML}
                [xml]$gpfile2 = Invoke-Command -Session $Server1Session -ScriptBlock { Get-GPOReport -Name "Windows Update Policy" -ReportType XML}
                $configurationNodes = $gpfile2.GPO.Computer.ExtensionData.Extension.Policy.Name
                $app1 = $gpfile2.gpo.Computer.ExtensionData.extension.MsiApplication 
            }
            Context "Application Deny List GPO Created and Configured" {
                It "Application Deny List GPO created"  {
                    Write-host "Verifying GPO created and applied (15 points) " (Get-Date).Ticks -ForegroundColor Cyan
                    Write-Host $line -ForegroundColor DarkGreen
                    $gpfile1 | Should -Not -BeNullOrEmpty
                }
                It "GPO should be linked to the Medical OUs" {
                    $gpfile1.GPO.LinksTo.SOMPath  | Should -Contain "medical-emr.com/Greenville/Medical"
                    $gpfile1.GPO.LinksTo.SOMPath  | Should -Contain "medical-emr.com/Pickens/Medical"
                }  
                It "Should configure the Run only specified Windows applications policy" {
                    $gpfile1.GPO.User.ExtensionData.Extension.Policy.Name | Should -Be "Run only specified Windows applications"
                }
                It "Should have the values cmd.exe and chrome.exe" {
                    $programs = $gpfile1.GPO.User.ExtensionData.Extension.Policy.ListBox.Value.ChildNodes.data 
                    $programs -contains "cmd.exe" | Should -BeTrue
                    $programs -contains "chrome.exe" | Should -BeTrue
                }
            }
            Context "Windows Update Policy GPO Created and Configured" {
                It "Corporate Windows Update Policy GPO created"  {
                    $gpfile2 | Should -Not -BeNullOrEmpty
                }
                It "GPO should be linked to the domain" {
                    $gpfile2.GPO.LinksTo.SOMPath | Should -Contain "medical-emr.com/Greenville"
                    $gpfile2.GPO.LinksTo.SOMPath | Should -Contain "medical-emr.com/Pickens"
                }
                 
                It "Should configure the Configure Automatic updates policy" {
                    $configurationNodes | Should -Contain "Configure Automatic Updates"
                }
                It "Should configure the Specify Intranet Microsoft Update service location policy"  {
                    $configurationNodes | Should -Contain "Specify intranet Microsoft update service location"
                }
                It "Should configure Auto download and schedule install" {
                    $gpfile2.GPO.Computer.ExtensionData.Extension.policy[0].DropDownList[0].Value.Name | Should -Be "4 - Auto download and schedule the install"
                }
                It "Updates should install on Saturday" {
                    $gpfile2.GPO.Computer.ExtensionData.Extension.policy[0].DropDownList[1].Value.Name | Should -Be "7 - Every Saturday"
                }
                It "Updates should install at 2:00 AM" {
                    $gpfile2.GPO.Computer.ExtensionData.Extension.policy[0].DropDownList[2].Value.Name | Should -Be "02:00"
                }
            }
        }
        Context "Active Directory Security" {
            It "Greenville-IT department can reset passwords for all users" {
                Write-host "Verifying AD Security (15 points) " (Get-Date).Ticks -ForegroundColor Cyan
                Write-Host $line -ForegroundColor DarkGreen

                $domainACL = Invoke-Command -Session $Server1Session -ScriptBlock { dsacls "DC=medical-emr,dc=com" | findstr /i "Greenville-IT" }
                $domainACL | Should -Contain "Allow MEDICAL-EMR\Greenville-IT       Reset Password"
            }
        }
    }
    Context "File system security on Medapps folder" -Tag FS {
        BeforeAll {
            $aclString = Invoke-Command -Session $Server1Session -ScriptBlock { (Get-Acl -Path C:\MedApps).AccessToString }
        }
        It "Created the MedApps folder"  {
            Invoke-Command -Session $Server1Session -ScriptBlock { Test-Path -Path C:\MedApps } | Should -BeTrue
        }
        It "The folder must be accessible over the network (shared)" {
            Invoke-Command -Session $Server1Session -ScriptBlock { Get-SmbShare -Name MedApps } | Should -BeTrue
            Invoke-Command -Session $Server1Session -ScriptBlock { (Get-SmbShareAccess -Name MedApps | ? AccountName -EQ "Everyone").AccessRight} | Should -BeIn "Full",0
        }
        
        It "Appropriate group(s) should have read NTFS permissions to MedApps" {
            $aclString | Should -BeLike "*MEDC1-MedApps-R Allow  Read*"
        }
        It "Appropriate group(s) should have Full Control NTFS permissions to MedApps"  {
            $aclString | Should -BeLike "*MEDC1-MedApps-FC Allow  Full*"
        }
        It "The Users group should not be in the ACL" {
            $aclstring | Should -Not -BeLike "*users allow*"
        }
    }

    Context "AD Replication Configuration" -Tag RPL {
        BeforeAll {
            $sites = "Pickens","Greenville"
            $actualsites = Invoke-Command -Session $Server1Session -ScriptBlock {(Get-ADReplicationSite -Filter *).name}
            $actualSubnets = Invoke-Command -Session $Server1Session -ScriptBlock { Get-ADReplicationSubnet -Filter *}
            $subnets = @{ "10.199.152.0/24" = "Greenville" ; "10.200.152.0/24" = "Pickens"}
            $sitelink = Invoke-Command -Session $Server1Session -ScriptBlock { Get-ADReplicationSiteLink -Identity "Greenville-Pickens"}
        }
        It "The required sites were created" {
            Write-host "Verifying AD Replication (10 points) " (Get-Date).Ticks -ForegroundColor Cyan
            Write-Host $line -ForegroundColor DarkGreen
           foreach ($site in $sites){
                $actualsites | Should -Contain $site 
            }
        }
        It "The required subnets were created in the correct sites"  {
            foreach ($subnet in $subnets.Keys)
            {
                $actualSubnets.name | Should -Contain $subnet
                $sitematch = $subnets.$subnet
                Invoke-Command -Session $Server1Session -ScriptBlock {(Get-ADReplicationSubnet -Identity $Using:subnet).site} | Should -BeLike "CN=$sitematch*"
            }
        }
        It "Greenville-Pickens site link object created"  {
            $sitelink | Should -Not -BeNullOrEmpty
        }
        It "Replication frequency is 45 minutes" {
            $sitelink.ReplicationFrequencyInMinutes | Should -Be 45
        }     
     }

    Context "CIS256-FP-Client Configuration" -Tag Client {
            BeforeAll {
                $IPSettings = @{
			        "LAN" = @{
				        "IPAddress" = "10.199.152.101"
				        "PrefixLength" = "24"
                        "DNSServer" = "10.199.152.1"
                        "Gateway" = "10.199.152.254"
		                "Name" = "MEClient1"
                        }
                }
                $ipconfig = Invoke-Command -Session $ClientSession -ScriptBlock { Get-NetAdapter | Get-NetIPAddress -AddressFamily IPv4 }
                $route = Invoke-Command -Session $ClientSession -ScriptBlock { Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0}
                $hostname = Invoke-Command -Session $ClientSession -ScriptBlock { hostname }
                $dnsserver = Invoke-Command -Session $ClientSession -ScriptBlock { Get-NetAdapter | Get-DnsClientServerAddress -AddressFamily IPv4 }
                $domainJoined  = Invoke-Command -Session $ClientSession -ScriptBlock { Test-ComputerSecureChannel }
            }
            Context "Network Configuration" {
        
                It "IP Address configured correctly" {
                    Write-host "Verifying Client renamed & joined to domain (5 points)`n" (Get-Date).Ticks -ForegroundColor Cyan
                    Write-Host $line -ForegroundColor DarkGreen
                    $ipconfig.ipaddress | Should -Be ($IPSettings.LAN.IPAddress)
                }
                It "Subnet mask configured correctly" {
                    $ipconfig.PrefixLength | Should -Be ($IPSettings.LAN.PrefixLength)    
                }
                It "Default Gateway configured correctly"  {
                    $route.NextHop | Should -Be ($IPSettings.LAN.Gateway)
                }
                It "DNS Server configured correctly" {
                    $dnsserver.serverAddresses | Should -Contain ($IPSettings.LAN.DNSServer)
                }
                It "Computer name configured correctly" {
                    $hostname | Should -Be ($IPSettings.LAN.Name)
                }
                It "Computer joined to the domain" {
                    $domainJoined | Should -BeTrue
                }
            }
        }

 }
 AfterAll {
        Write-Host "`t" (Get-Date).Ticks -ForegroundColor Cyan
        Write-Host "`t" (Get-WMIObject -Class Win32_computerSystemProduct).UUID -ForegroundColor Cyan
        $scriptName=&{$MyInvocation.ScriptName}
        Write-Host (Get-FileHash $scriptName).Hash -ForegroundColor Cyan        
        Write-Host " " $scriptName -ForegroundColor Cyan
        Get-PSSession | Remove-PSSession
 }