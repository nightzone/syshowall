<#
syshowall - Synergy Configuration Collector
Written by Sergii Oleshchenko
#>
$scriptVersion = "1.4 PS"

# create class to handle SSL errors
$code = @"
public class SSLHandler
{
    public static System.Net.Security.RemoteCertificateValidationCallback GetSSLHandler()
    {
       return new System.Net.Security.RemoteCertificateValidationCallback((sender, certificate, chain, policyErrors) => { return true; });
    }

}
"@

#compile the class
if (-not ([System.Management.Automation.PSTypeName]'SSLHandler').Type)
{
    Add-Type -TypeDefinition $code
}

# to support zipping 
Add-Type -AssemblyName System.IO.Compression.FileSystem

Write-Host ("syshowall v" + $scriptVersion + " - Synergy Configuration Collector`n")


# Timeframe for Audit Log
$historyDate = (Get-Date).AddDays(-5).ToString("yyyy-MM-dd")

# REST URIs and file names where to save output

# Appliance URI
$Appliance = @(
             ("/controller-state.json",                          'controller-state.txt'),    # added in v1.4
            ("/rest/appliance/configuration/time-locale",       'time-locale.txt'),         # added to collect Time settings on the appliance
            ("/rest/appliance/device-read-community-string",    'device-read-community-string.txt'),
            ("/rest/appliance/eula/status",                     'eula-status.txt'),             # attention
            ("/rest/appliance/firmware/notification",           'firmware-notification.txt'),   # attention
            ("/rest/appliance/firmware/pending",                'firmware-pending.txt'),        # attention
            ("/rest/appliance/firmware/verificationKey",        'firmware-verificationkey.txt'),
            ("/rest/appliance/ha-nodes",                        'ha-nodes.txt'),             # added to collect active/standby composer
            ("/rest/appliance/health-status",                   'health-status.txt'),
            ("/rest/appliance/network-interfaces",              'network-interfaces.txt'),
    		    ("/rest/appliance/network-interfaces/mac-addresses",    'network-interfaces-mac.txt'),
            ("/rest/appliance/notifications/email-config",      'notification-email-config.txt'),
    		    ("/rest/appliance/notifications/test-email-config",     'notification-test-email-config.txt'),
            ("/rest/appliance/progress",                        'progress.txt'),
            ("/rest/appliance/proxy-config",                    'proxy-config.txt'),                # added in v1.4
            ("/rest/appliance/settings/serviceaccess",          'settings-serviceaccess.txt'),   # attention
            ("/rest/appliance/snmpv3-trap-forwarding/destinations", 'snmpv3-destinations.txt'),      # added in v1.4
            ("/rest/appliance/snmpv3-trap-forwarding/users",        'snmpv3-users.txt'),          # added in v1.4
            ("/rest/appliance/ssh-access",                      'ssh-access.txt'),
            ("/rest/appliance/trap-destinations",               'trap-destinations.txt'),
            ("/rest/backups",                                   'backups.txt'),
    		    ("/rest/backups/config",                            'backups-config.txt'),
            ("/rest/deployment-servers/image-streamer-appliances",  'image-streamer-appliances.txt'),    # added to collect IS appliance details
            ("/rest/domains",                                   'domains.txt'),
            ("/rest/domains/schema",                            'domains-schema.txt'),
            ("/rest/firmware-drivers",                          'firmware-drivers.txt'),
            ("/rest/global-settings",                           'global-settings.txt'),
            ("/rest/licenses",                                  'licenses.txt'),
    		    ("/rest/remote-syslog",                             'remote-syslog.txt'),
            ("/rest/repositories",                              'repositories.txt'),                     # added in v1.4     need to check
            ("/rest/restores",                                  'restores.txt'),
    		    ("/rest/scopes",                                    'scopes.txt'),
            ("/rest/version",                                   'version.txt')
)

#HP OneView Version
$hponeviewversion = @(
       ("/rest/appliance/nodeinfo/version", "version.txt"),
		   ("")
)


# FC-SANS
$fcsans = @(
            ("/rest/fc-sans/device-managers",   'device-managers.txt'),
            ("/rest/fc-sans/managed-sans",      'managed-sans.txt'),
            ("/rest/fc-sans/providers",         'providers.txt'),
            ("/rest/fc-sans/endpoints",         'endpoints.txt')
)

# Security
$security = @(
            ("/rest/active-user-sessions",                      'active-user-sessions.txt'),
            ("/rest/appliance-encryption-key",                  'appliance-encryption-key.txt'),
            ("/rest/authz/category-actions",                    'authz-category-actions.txt'),
            ("/rest/certificates",                              'certificates.txt'),
            ("/rest/certificates/ca",                           'certificates-ca.txt'),
            ("/rest/certificates/https",                        'certificates-https.txt'),
            ("/rest/logindetails",                              'logindetails.txt'),
            ("/rest/logindomains",                              'logindomains.txt'),
            ("/rest/logindomains/global-settings",              'logindomains-global-settings.txt'),
            ("/rest/logindomains/grouptorolemapping",           'logindomains-grouptorolemapping.txt'),
            ("/rest/roles",                                     'roles.txt'),
            ("/rest/security-standards/modes/current-mode",     'security-current-mode.txt'),
            ("/rest/security-standards/protocols",              'security-protocols.txt'),
            ("/rest/appliance/sshhostkeys",                     'sshhostkeys.txt'),
            ("/rest/users",                                     'users.txt')
)

#Activity
$activity =
@(
            (("/rest/audit-logs?filter=`"DATE >= '" + $historyDate + "'`""),                 'audit-logs.txt'),
    		("/rest/alerts?start=0&count=300&sort=created:descending",                       'alerts.txt'),
    		("/rest/events?start=0&count=300&sort=created:descending",                       'events.txt'),
            ("/rest/tasks?sort=created:descending&filter=`"created ge {2 days ago}`"",       'tasks.txt')
)

#Servers
$servers = @(
    		("/rest/connections",                  'connections.txt'),
    		("/rest/server-hardware",              'server-hardware.txt'),
    		("/rest/server-hardware-types",        'server-hardware-types.txt'),
    		("/rest/server-profiles",              'server-profiles.txt'),
    		("/rest/server-profile-templates",     'server-profile-templates.txt'),
    		("/rest/server-hardware/*/firmware",   'firmware.txt')                    # added to collect server FW details
)

#Enclosures
$enclosures= @(
    		("/rest/logical-enclosures",      'logical-enclosures.txt'),
    		("/rest/enclosure-groups",        'enclosure-groups.txt'),
    		("/rest/enclosures",              'enclosures.txt')
		)

#Networking
$networking = @(
    		    ("/rest/connection-templates",            'connection-templates.txt'),
            ("/rest/connections",                     'connections.txt'),
    		    ("/rest/ethernet-networks",               'ethernet-networks.txt'),
            ("/rest/fabric-managers",                 'fabric-managers.txt'),       # added in v1.4
            ("/rest/fabrics",                         'fabrics.txt'),
    		    ("/rest/fc-networks",                     'fc-networks.txt'),
            ("/rest/fcoe-networks",                   'fcoe-networks.txt'),       # added in v1.4
            ("/rest/interconnect-link-topologies",    'interconnect-link-topologies.txt'),
            ("/rest/interconnect-types",              'interconnect-types.txt'),
    		    ("/rest/interconnects",                   'interconnects.txt'),
            ("/rest/internal-link-sets",              'internal-link-sets.txt'),
    		    ("/rest/logical-downlinks",               'logical-downlinks.txt'),
    		    ("/rest/logical-interconnect-groups",     'logical-interconnect-groups.txt'),
    		    ("/rest/logical-interconnects",           'logical-interconnects.txt'),
            ("/rest/logical-switch-groups",           'logical-switch-groups.txt'),       # added in v1.4
            ("/rest/logical-switches",                'logical-switches.txt'),       # added in v1.4
    		    ("/rest/network-sets",                    'network-sets.txt'),
  	        ("/rest/switches",                        'switches.txt'),
    		    ("/rest/uplink-sets",                     'uplink-sets.txt')
)

#Storage
$storage = @(
    		("/rest/storage-pools",               'storage-pools.txt'),
        ("/rest/storage-systems",             'storage-systems.txt'),
    		("/rest/storage-volumes",             'storage-volumes.txt'),
    		("/rest/storage-volume-templates",    'storage-volume-templates.txt'),
    		("/rest/storage-volume-attachments",  'storage-volume-attachments.txt')
)

#Hypervisor
$hypervisor = @(
    		("/rest/hypervisor-cluster-profiles", 'hypervisor-cluster-profiles.txt'),
    		("/rest/hypervisor-host-profiles",    'hypervisor-host-profiles.txt'),
        ("/rest/hypervisor-managers",         'hypervisor-managers.txt')
)

#Deployment
$deployment = @(
    		("/rest/os-deployment-plans/",                             'os-deployment-plans.txt'),
    		("/rest/deployment-servers",                              'deployment-servers.txt'),
        ("/rest/deployment-servers/image-streamer-appliances",    'image-streamer-appliances.txt'),
        ("/rest/deployment-servers/network",                      'network.txt')
)

#Facilities
$facilities = @(
    		("/rest/datacenters",     'datacenters.txt'),
    		("/rest/power-devices",   'power-devices.txt'),
    		("/rest/racks",           'racks.txt')
)

#Uncategorized
$uncategorized = @(
    		("/rest/migratable-vc-domains",  'migratable-vc-domains.txt'),
    		("/rest/unmanaged-devices",       'unmanaged-devices.txt')
)

#Index
#$index = (
#		"/rest/index/associations",
#		"/rest/index/associations/resources",
#		"/rest/index/resources",
#		"/rest/index/resources/aggregated",
#		"/rest/index/trees",
#		"/rest/index/trees/minified",
#		"/rest/labels"
#)

# SAS Storage
$sas= @(
      ("/rest/drive-enclosures",                  'drive-enclosures.txt'),
      ("/rest/sas-interconnect-types",            'sas-interconnect-types.txt'),
    	("/rest/sas-interconnects",                 'sas-interconnects.txt'),
    	("/rest/sas-logical-interconnect-groups",   'sas-logical-interconnect-groups.txt'),
    	("/rest/sas-logical-interconnects",         'sas-logical-interconnects.txt'),
    	("/rest/sas-logical-jbod-attachments",      'sas-logical-jbod-attachments.txt'),
    	("/rest/sas-logical-jbods",                 'sas-logical-jbods.txt')
)

# Service Automation
$sa = @(
            ("/rest/support/channel-partners",              'channel-partners.txt'),
            ("/rest/support/configuration",                 'configuration.txt'),
            ("/rest/support/contacts",                      'contacts.txt'),
            # ("/rest/support/datacenters",                   'datacenters.txt'),
            # ("/rest/support/data-collections",              'data-collections.txt'),
            # ("/rest/support/enclosures",                    'enclosures.txt'),
            ("/rest/support/portal-registration",           'portal-registration.txt'),
            ("/rest/support/registration",                  'registration.txt'),
            ("/rest/support/schedules",                     'schedules.txt')
            # ("/rest/support/server-hardware",               'server-hardware.txt'),
            # ("/rest/support/sites",                         'sites.txt')
)

# id-pools
$idpools= @(
        ("/rest/id-pools/schema",               'schema.txt'),
        ("/rest/id-pools/ipv4/subnets",         'subnets.txt'),
        ("/rest/id-pools/ipv4/ranges/schema",   'ipv4-ranges-schema.txt'),
        ("/rest/id-pools/vmac/ranges/schema",   'vmac-ranges-schema.txt'),
        ("/rest/id-pools/vsn/ranges/schema",    'vsn-ranges-schema.txt'),
        ("/rest/id-pools/vwwn/ranges/schema",   'vwwn-ranges-schema.txt')
)

# Identifies latest supported API version
function GetXAPIversion([String]$applianceIP)
{

  $resturi = "/rest/version"
  $url = "https://" + $applianceIP + $resturi
  $xapiheader = @{}
  $xapiheader.Add("Content-Type","application/json")
  $xapiheader.Add("Accept-Language", "en_US")

  try
  {
    #disable SSL checks using new class
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()
    $result = Invoke-RestMethod -Uri $url -Method GET -Headers $xapiheader
    $xapi = $result.currentVersion
  }
  catch
  {
    $xapi = 0
  }
  finally
  {
    #enable ssl checks again
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
  }

  return $xapi
}

# Authenticate to appliance and return SessionID key
function create_session([String]$applianceIP, [String]$Login, [String]$Password, [int]$xapi)
{
  $resturi = "/rest/login-sessions"
  $url = "https://" + $applianceIP + $resturi
  $header.Add("Content-Type","application/json")
  $header.Add("Accept-Language", "en_US")
  $header.Add("X-Api-Version", $xapi.ToString())
  $sessionID = ""

  Write-Host "Trying to log on as" $Login "..."
  # Check if domain credentials
  if($Login.Contains("\"))
  {
    $domain = $Login.Split("\")[0]
    $username = $Login.Split("\")[1]
  }
  else
  {
    $domain = ""
    $username = $Login
  }

  $body = [Ordered]@{
       "authLoginDomain" = $domain.ToUpper()
       "password"        = $Password
       "userName"        = $username
       "loginMsgAck"     = 'true'}

  $bodyJSON = ConvertTo-Json $body

  try
  {
    #disable SSL checks using new class
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()
    $result = Invoke-RestMethod -Uri $url -Method POST -Headers $header -Body $bodyJSON
    $sessionID = $result.sessionID
    Write-Host "Logged on successfully."
  }
  catch
  {
    Write-Host "`nLogin failed.`nPlease check credentials."
  }
  finally
  {
    #enable ssl checks again
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
  }

  return $sessionID
}

function extract_data([String]$ResourceName, [System.Array]$Resources)
{
    Write-Host "Extracting $ResourceName details....... " -NoNewline

    foreach($resource in $Resources)
    {
		if($resource.length -gt 0)
		{

			$OutFileName = $ResourceName + '_' + $resource[1]
            $filepath = Join-Path $resultdir $ResourceName | Join-Path -ChildPath $OutFileName
            $url = "https://" + $applianceIP + $resource[0]

            #get count value
            $countMax = 100000
            if ($resource[0].Contains("?"))
            {
                $params = $resource[0].split("?")[1]
                $params_list = $params.split("&")
                foreach ($param in $params_list)
                {
                    if($param.Contains("count"))
                    {
                        $countMax = [int]$param.split("=")[1]
                    }
                }
            }

			try
			{
                #disable SSL checks using new class
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

                $resp = Invoke-RestMethod -Uri $url -Method GET -Headers $header

                while(($resp.nextPageUri -ne $null) -and ($resp.count -lt $countMax))
                {
                    $url = "https://" + $applianceIP + $resp.nextPageUri
                    $resp1 = Invoke-RestMethod -Uri $url -Method GET -Headers $header
                    $resp.members += $resp1.members
                    $resp.count += $resp1.count
                    $resp.nextPageUri = $resp1.nextPageUri
                }

				$jsonResp = $resp | ConvertTo-Json -Depth 99

				#Check if the response is an array
				if($jsonResp.members.value.count -gt 0)
				{
				   for($index = 0; $index -lt $jsonResp.members.value.count; $index++)
				   {
					   Write-Host $jsonResp.members.value[$index]
				   }
				}
			}
			catch
			{
                $jsonResp = "StatusCode: " + $_.Exception.Response.StatusCode.value__ + "`nStatusDescription: " + $_.Exception.Response.StatusDescription
			}
            finally
            {
                #enable ssl checks again
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }


			if(!(Test-Path $resultDir/$ResourceName))
			{
				New-Item $resultDir/$ResourceName -ItemType Directory | Out-Null
			}

            $jsonResp | Out-File $filepath
		}
    }

    Write-Host "Done"
}

function extract_all([String]$applianceIP, [String]$Login, [String]$Password)
{
	# Connect to the Appliance
	Write-Host "`nConnectivity check......" $applianceIP "...... " -NoNewline

    $xapi = GetXAPIversion -applianceIP $applianceIP
    if ($xapi -gt 0)
    {
        Write-Host "Pass."
        $sessionID = create_session -applianceIP $applianceIP -Login $Login -Password $password -xapi $xapi
        $header.Add("Auth", $sessionID)
    }
    else
    {
        Write-Host "Fail."
        Write-Host "Check IP settings and network connectivity to Synergy Appliance."
        $sessionID = ""
    }

	if ($sessionID -ne "")
	{

        # Save Progress Preference and set it to silent
        $oldProgressPreference = $progressPreference 
        $progressPreference = 'SilentlyContinue'

		# Create Temporary Output Directory
		$scriptDir = $PSScriptRoot
		$currentTime = Get-Date -Format "yyyyMMddHHmmss".toString()
		$resultDir = Join-Path $scriptDir ("result" + $currentTime)

		if(!(Test-Path ($resultDir))){
					New-Item $resultDir -ItemType Directory | Out-Null
		}
		else {
			Remove-Item -Path $resultDir -Recurse
			New-Item $resultDir -ItemType Directory | Out-Null
		}

		#Discover resources
		Write-Host `n">> Extracting Data <<"

		#Appliance
		extract_data -ResourceName "Appliance" -Resources $Appliance

		#HP OneView Version
		extract_data -ResourceName "HP-OneView-Version" -Resources $hponeviewversion

		#FC SAN
		extract_data -ResourceName "FC-SAN" -Resources $fcsans

		#security
		extract_data -ResourceName "Security" -Resources $security

		#Activity
		extract_data -ResourceName "Activity" -Resources $activity

		#Servers
		extract_data -ResourceName "Servers" -Resources $servers

		#Enclosures
		extract_data -ResourceName "Enclosures" -Resources $enclosures

		#Networking
		extract_data -ResourceName "Networking" -Resources $networking

		#Storage
		extract_data -ResourceName "Storage" -Resources $storage

		#Hypervisor
		extract_data -ResourceName "Hypervisor" -Resources $hypervisor

		#Deployment
		extract_data -ResourceName "Deployment" -Resources $deployment

		#Facilities
		extract_data -ResourceName "Facilities" -Resources $facilities

		#Uncategorized
		extract_data -ResourceName "Uncategorized" -Resources $uncategorized

		#Index
		#extract_data -ResourceName "Index" -Resources $index

		#SAS
		extract_data -ResourceName "SAS-Storage" -Resources $sas

		#Service Automation
		extract_data -ResourceName "Service-Automation" -Resources $sa

		#id-pools
		extract_data -ResourceName "ID-Pools" -Resources $idpools

		# Disconnect
        $url = "https://" + $applianceIP + "/rest/login-sessions"
	    try
		{
            #disable SSL checks using new class
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()
            Write-Host "`nDisconnect from Appliance:" $applianceIP
            $resp = Invoke-RestMethod -Uri $url -Method Delete -Headers $header
		}
		catch
		{
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
		}
        finally
        {
            #enable ssl checks again
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        }

		# Create and write info.txt
		$syshowallVersion = [pscustomobject]@{
			description =  'Synergy Configuration Collector'
			application = 'syshowall PS'
			version = $scriptVersion
			appliance = $applianceIP
			login =  $Login
			timestamp = Get-Date -Format "yyyy-MM-dd hh:mm:ss".ToString()
			eTag = $null
		}

		$syshowallVersion | ConvertTo-Json -Depth 99 | Out-File (Join-Path $resultdir "info.txt")

		Start-Sleep -Seconds 5

		if(Test-Path $resultDir){
					$currentTime = Get-Date -Format "yyyyMMddHHmmss".toString()
					$archiveName = "syconf-" + $applianceIP + "-" + $currentTime + ".zip"
					$archivePath = Join-Path $scriptDir $archiveName
                   
                    if(Test-Path $archivePath){
	                     Remove-Item -Path $archivePath 
                    }
                    try
                    {
                        Invoke-Command -ScriptBlock {[System.IO.Compression.ZipFile]::CreateFromDirectory($resultDir, $archivePath)} | Wait-Job
                        Remove-Item -Path $resultDir -Recurse
                        Write-Host "`nConfiguration saved to file:" $archiveName
                    }
                    catch
                    {
                        Write-Host "`nCannot create .zip archive"
                        Write-Host "Configuration located in folder:" $resultDir.Split("\")[-1]
                    }
                    finally
                    {
                        # Set progress Preference back
                        $progressPreference = $oldProgressPreference

                    }

		}
		else {
			# Folder cannot be removed
		}

	}

}

# MAIN SCRIPT

# Global Variable for Header parameter of Invoke-RestMethod
$header = @{}

# Get path for iplist.txt file
$scriptDir = $PSScriptRoot
$iplistPath = Join-Path $scriptDir "iplist.txt"
# if iplist.txt exist - collect configs from systems in file
if(Test-Path $iplistPath) 
{
    Write-Host "List of IP 'iplist.txt' found. `nPlease enter credentials.`n"

    $username = Read-Host "Login"
    [SecureString]$password = Read-Host -AsSecureString "Password"
    $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

    foreach($ip in (Get-Content $iplistPath))
    {
        $header = @{}
        
        extract_all -applianceIP $ip -Login $username -Password $decryptPassword

        Write-Host "`n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    }
}
else  # collect config for single system
{

    while (-not $header['Auth'])
    {

        $applianceIP = Read-Host "Appliance IP"
        $username = Read-Host "Login"
        [SecureString]$password = read-host -AsSecureString "Password"
        $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

        $header = @{}

        # Collect Configuration
        extract_all -applianceIP $applianceIP -Login $username -Password $decryptPassword
    
        Write-Host "`n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>`n"        
    }
}

Read-Host "Press <Enter> to exit..." 