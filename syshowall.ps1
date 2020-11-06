<#
syshowall - Synergy Configuration Collector
Written by Sergii Oleshchenko
email: sergii.oleshchenko@hpe.ua
#>
$scriptVersion = "2.1.1 PS"

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

# added for JavaScript serialized object
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")

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
$historyDateTasks = (Get-Date).AddDays(-2).ToString("yyyy-MM-dd")

# REST URIs and file names where to save output

# Appliance URI
$Appliance = @(
             ("/controller-state.json",                          'controller-state.txt'),    # added in v1.4
            ("/rest/appliance/configuration/time-locale",       'time-locale.txt'),         # added to collect Time settings on the appliance
            ("/rest/appliance/device-read-community-string",    'device-read-community-string.txt'),
            ("/rest/appliance/eula/status",                     'eula-status.txt'),
            ("/rest/appliance/firmware/notification",           'firmware-notification.txt'),
            ("/rest/appliance/firmware/pending",                'firmware-pending.txt'),
            ("/rest/appliance/firmware/verificationKey",        'firmware-verificationkey.txt'),
            ("/rest/appliance/ha-nodes",                        'ha-nodes.txt'),             # added to collect active/standby composer
            ("/rest/appliance/health-status",                   'health-status.txt'),
            ("/rest/appliance/network-interfaces",              'network-interfaces.txt'),
    	    ("/rest/appliance/network-interfaces/mac-addresses",    'network-interfaces-mac.txt'),
            ("/rest/appliance/nodeinfo/status",                'nodeinfo-status.txt'),
            ("/rest/appliance/nodeinfo/version",               'nodeinfo-version.txt'),
            ("/rest/appliance/notifications/email-config",      'notification-email-config.txt'),
    	    ("/rest/appliance/notifications/test-email-config",     'notification-test-email-config.txt'),
            ("/rest/appliance/progress",                        'progress.txt'),
            ("/rest/appliance/proxy-config",                    'proxy-config.txt'),                # added in v1.4
            ("/rest/appliance/settings/serviceaccess",          'settings-serviceaccess.txt'),   # attention
            ("/rest/appliance/snmpv3-trap-forwarding/destinations", 'snmpv3-destinations.txt'),      # added in v1.4
            ("/rest/appliance/snmpv3-trap-forwarding/users",        'snmpv3-users.txt'),          # added in v1.4
            ("/rest/appliance/ssh-access",                      'ssh-access.txt'),
            ("/rest/appliance/static-routes",                    'static-routes.txt'),          # v2.1
            ("/rest/appliance/trap-destinations",               'trap-destinations.txt'),
            ("/rest/backups",                                   'backups.txt'),
    		("/rest/backups/config",                            'backups-config.txt'),
            ("/rest/deployment-servers/image-streamer-appliances",  'image-streamer-appliances.txt'),    # added to collect IS appliance details
            ("/rest/domains",                                   'domains.txt'),
            ("/rest/domains/schema",                            'domains-schema.txt'),
            ("/rest/firmware-drivers",                          'firmware-drivers.txt'),
            ("/rest/global-settings",                           'global-settings.txt'),
            ("/rest/hardware-compliance",                       'hardware-compliance.txt'),
            ("/rest/hw-appliances",                             'hw-appliances.txt'),
            ("/rest/index/resources?query=`"NOT scopeUris:NULL`"", 'scopes-resources.txt'),
            ("/rest/licenses",                                  'licenses.txt'),
    		("/rest/remote-syslog",                             'remote-syslog.txt'),
            ("/rest/repositories",                              'repositories.txt'),                     # added in v1.4
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
            ("/rest/fc-sans/endpoints",         'endpoints.txt'),
            ("/rest/fc-sans/zones",             'zones.txt')
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
            ("/rest/secure-data-at-rest",                       'secure-data-at-rest.txt'),
            ("/rest/security-standards/modes",                  'security-modes.txt'),
            ("/rest/security-standards/modes/current-mode",     'security-current-mode.txt'),
            ("/rest/security-standards/protocols",              'security-protocols.txt'),
            ("/rest/appliance/sshhostkeys",                     'sshhostkeys.txt'),
            ("/rest/users",                                     'users.txt')
)

#Activity
$activity =
@(
            (("/rest/audit-logs?filter=`"DATE >= '" + $historyDate + "'`""),                 'audit-logs.txt'),
            (("/rest/audit-logs/settings"),                                                  'audit-logs-settings.txt'),
            ("/rest/alerts?start=0&count=300&sort=created:descending",                       'alerts.txt'),
            ("/rest/alerts?sort=created:descending&filter=`"serviceEventSource='true'`"",    'alerts-service-events.txt'), # v2.1
    		("/rest/events?start=0&count=300&sort=created:descending",                       'events.txt'),
            (("/rest/tasks?sort=created:descending&filter=`"created ge " + $historyDateTasks + "T00:00:01.830Z`""),  'tasks.txt')
)

#Servers
$servers = @(
    		("/rest/connections",                  'connections.txt'),
    		("/rest/server-hardware",              'server-hardware.txt'),
    		("/rest/server-hardware-types",        'server-hardware-types.txt'),
    		("/rest/server-profiles?count=2048",   'server-profiles.txt'),             # added count to 1.7.1 to work with OV 5.00.02
    		("/rest/server-profile-templates",     'server-profile-templates.txt'),
    		("/rest/server-hardware/*/firmware",   'firmware.txt'),                    # added to collect server FW details
            ("/rest/rack-managers",                'rack-managers.txt')
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
            ("/rest/internal-link-sets",              'internal-link-sets.txt'),    # v2.1
    		("/rest/logical-downlinks",               'logical-downlinks.txt'),     # v2.1
    		("/rest/logical-interconnect-groups",     'logical-interconnect-groups.txt'),
    		("/rest/logical-interconnects",           'logical-interconnects.txt'),
            ("/rest/logical-switch-groups",           'logical-switch-groups.txt'),       # added in v1.4
            ("/rest/logical-switches",                'logical-switches.txt'),       # added in v1.4
    		("/rest/network-sets",                    'network-sets.txt'),
            ("/rest/switch-types",                    'switch-types.txt'),
  	        ("/rest/switches",                        'switches.txt'),
    		("/rest/uplink-sets",                     'uplink-sets.txt')
)

#Storage
$storage = @(
    		("/rest/storage-pools",               'storage-pools.txt'),
            ("/rest/storage-systems",             'storage-systems.txt'),
    		("/rest/storage-volume-attachments",  'storage-volume-attachments.txt'),
            ("/rest/storage-volume-sets",         'storage-volume-sets.txt'),        # added in v2.0
    		("/rest/storage-volume-templates",    'storage-volume-templates.txt'),
            ("/rest/storage-volumes",             'storage-volumes.txt')
)

#Hypervisor
$hypervisor = @(
    		("/rest/hypervisor-cluster-profiles", 'hypervisor-cluster-profiles.txt'),
    		("/rest/hypervisor-host-profiles",    'hypervisor-host-profiles.txt'),
            ("/rest/hypervisor-managers",         'hypervisor-managers.txt')
)

#Deployment
$deployment = @(
    		("/rest/os-deployment-plans/",                            'os-deployment-plans.txt'),
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
            ("/rest/support/entitlements",                   'entitlements.txt'),
            # ("/rest/support/datacenters",                   'datacenters.txt'),
            # ("/rest/support/data-collections",              'data-collections.txt'),
            # ("/rest/support/enclosures",                    'enclosures.txt'),
            ("/rest/support/portal-registration",           'portal-registration.txt'),
            ("/rest/support/registration",                  'registration.txt'),
            ("/rest/support/schedules",                     'schedules.txt'),
            ("/rest/support/sites/default",                 'sites-default.txt')
            # ("/rest/support/server-hardware",               'server-hardware.txt'),
            # ("/rest/support/sites",                         'sites.txt')
)

# id-pools
$idpools= @(
        ("/rest/id-pools/schema",               'schema.txt'),
        ("/rest/id-pools/ipv4/ranges/schema",   'ipv4-ranges-schema.txt'),
        ("/rest/id-pools/ipv4/subnets",         'subnets.txt'),
        ("/rest/id-pools/ipv6/ranges/schema",   'ipv6-ranges-schema.txt'),   # added v2.0
        ("/rest/id-pools/ipv6/subnets",         'ipv6-subnets.txt'),         # added v2.0
        ("/rest/id-pools/vmac",                 'vmac.txt'),
        ("/rest/id-pools/vmac/ranges/schema",   'vmac-ranges-schema.txt'),
        ("/rest/id-pools/vsn",                  'vsn.txt'),
        ("/rest/id-pools/vsn/ranges/schema",    'vsn-ranges-schema.txt'),
        ("/rest/id-pools/vwwn",                 'vwwn.txt'),
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
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12       # added in v2.0

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
       "authLoginDomain" = $domain
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

                $respWeb = (Invoke-WebRequest -Uri $url -Method GET -Headers $header).Content    #Invoke-RestMethod
                $resp = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($respWeb)

                $count = 0
                while(($null -ne $resp.nextPageUri) -and ($resp.count -lt $countMax) -and ($resp.count -lt $resp.total) -and ($count -le 1000))
                {
                    $url = "https://" + $applianceIP + $resp.nextPageUri
                 #   $resp1 = Invoke-RestMethod -Uri $url -Method GET -Headers $header
                    $resp1Web = (Invoke-WebRequest -Uri $url -Method GET -Headers $header).Content
                    $resp1 = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($resp1Web)
                    $resp.members += $resp1.members
                    $resp.count += $resp1.count
                    $resp.nextPageUri = $resp1.nextPageUri
                    $count += 1
                    if($resp1.count -eq 0) {break}
                }

				$jsonResp = $resp | ConvertTo-Json -Depth 99

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
           # Write-Host $jsonResp
            $jsonResp | Out-File $filepath
		}
    }

    Write-Host "Done"
}

function extract_data_by_uri([String]$ResourceName, [String]$FileName, [String]$RestRequest, [String]$SearchParameter, [Int]$UriLength)
{

			$OutFileName = $ResourceName + '_' + $FileName
            $filepath = Join-Path $resultdir $ResourceName | Join-Path -ChildPath $OutFileName
            $url = "https://" + $applianceIP + $RestRequest

            #get count value
            $countMax = 100000
            if ($RestRequest.Contains("?"))
            {
                $params = $RestRequest.split("?")[1]
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

                $respWeb = (Invoke-WebRequest -Uri $url -Method GET -Headers $header).Content    #Invoke-RestMethod
                $resp = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($respWeb)

                $count = 0
                while(($null -ne $resp.nextPageUri) -and ($resp.count -lt $countMax) -and ($resp.count -lt $resp.total) -and ($count -le 1000))
                {
                    $url = "https://" + $applianceIP + $resp.nextPageUri
                    $resp1Web = (Invoke-WebRequest -Uri $url -Method GET -Headers $header).Content
                    $resp1 = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($resp1Web)
                    $resp.members += $resp1.members
                    $resp.count += $resp1.count
                    $resp.nextPageUri = $resp1.nextPageUri
                    $count += 1
                    if($resp1.count -eq 0) {break}
                }

                # check if remote support collection
                $isRScollection = $false
                if ($SearchParameter.Contains("hwuri"))
                {
                   $isRScollection = $true
                }

                $uriList = @()

                if($resp.ContainsKey('members'))
                {
                    # extract uris for key in each member
                   foreach ($item in $resp.members)
                   {
                        $uri_data = $item.$SearchParameter
                        $uriList += $uri_data

                        # for RS leave only devices with entitlement
                        if ($isRScollection -and ($null -eq $item.entitlementStatus))
                        {
                           $uriList = $uriList -ne $uri_data
                        }
                   }
                }
                else
                {
                     $uri_data = $resp.$SearchParameter
                     $uriList += $uri_data
                }

                # for RS insert 'support' to uri
                if ($isRScollection)
                {
                   $uriList = $uriList.ForEach({$_.insert(6,'support/')})
                }

                # get required uri length, 0 means complete uri
                if ($UriLength -gt 0)
                {
                     for($i=0; $i -lt $uriList.length; $i++)
                     {
                         $splitList = $uriList[$i].split("/")[0..$UriLength]
                         $uriList[$i] = $splitList -join "/"
                     }
                }
                # leave only unique uries
                $uriList = $uriList | Get-Unique


              $data = [Ordered]@{
                   "count"       = 0
                   "members"     = @()
                   "eTag"        = '' }

                foreach($uri in $uriList)
                {
                    $url = "https://" + $applianceIP + $uri
                    $respWeb = (Invoke-WebRequest -Uri $url -Method GET -Headers $header).Content
                    $resp = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($respWeb)

                   if($resp.ContainsKey('members'))
                   {
                      $data.members += $resp.members
                      $data.count += $resp.count
                   }
                   else
                   {
                      $data.members += $resp
                      $data.count += 1
                   }
                }

				$jsonResp = $data | ConvertTo-Json -Depth 99

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


function extract_resource_uri_list([String]$RestUri, [String]$SearchField, [Int]$UriLength)
{

            $url = "https://" + $applianceIP + $RestUri
            $uriList = @()

            #get count value
            $countMax = 100000
            if ($RestUri.Contains("?"))
            {
                $params = $RestUri.split("?")[1]
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

                $respWeb = (Invoke-WebRequest -Uri $url -Method GET -Headers $header).Content    #Invoke-RestMethod
                $resp = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($respWeb)

                $count = 0
                while(($null -ne $resp.nextPageUri) -and ($resp.count -lt $countMax) -and ($resp.count -lt $resp.total) -and ($count -le 1000))
                {
                    $url = "https://" + $applianceIP + $resp.nextPageUri
                    $resp1Web = (Invoke-WebRequest -Uri $url -Method GET -Headers $header).Content
                    $resp1 = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($resp1Web)
                    $resp.members += $resp1.members
                    $resp.count += $resp1.count
                    $resp.nextPageUri = $resp1.nextPageUri
                    $count += 1
                    if($resp1.count -eq 0) {break}
                }

                # check if remote support collection
                $isRScollection = $false
                if ($SearchField.Contains("hwuri"))
                {
                   $isRScollection = $true
                }

                if($resp.ContainsKey('members'))
                {
                    # extract uris for key in each member
                   foreach ($item in $resp.members)
                   {
                        $uri_data = $item.$SearchField
                        $uriList += $uri_data

                        # for RS leave only devices with entitlement
                        if ($isRScollection -and ($null -eq $item.entitlementStatus))
                        {
                           $uriList = $uriList -ne $uri_data
                        }
                   }
                }
                else
                {
                    $uri_data = $resp.$SearchField
                    $uriList += $uri_data
                }

                # for RS insert 'support' to uri
                if ($isRScollection)
                {
                   $uriList = $uriList.ForEach({$_.insert(6,'support/')})
                }

                # get required uri length, 0 means complete uri
                if ($UriLength -gt 0)
                {
                     for($i=0; $i -lt $uriList.length; $i++)
                     {
                         $splitList = $uriList[$i].split("/")[0..$UriLength]
                         $uriList[$i] = $splitList -join "/"
                     }
                }
                # leave only unique uries
                $uriList = $uriList | Get-Unique

			}
			catch
			{
                #$jsonResp = "StatusCode: " + $_.Exception.Response.StatusCode.value__ + "`nStatusDescription: " + $_.Exception.Response.StatusDescription
			}
            finally
            {
                #enable ssl checks again
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }

    return $uriList
}

function extract_data_by_uri_list([String]$ResourceName, [String]$FileName, [Array]$UriList, [String]$AppendUri)
{

			$OutFileName = $ResourceName + '_' + $FileName
            $filepath = Join-Path $resultdir $ResourceName | Join-Path -ChildPath $OutFileName

            #get count value
           # $countMax = 100000

              $data = [Ordered]@{
                   "count"       = 0
                   "members"     = @()
                   "eTag"        = '' }

           try
           {

                #disable SSL checks using new class
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

                foreach($uri in $UriList)
                {
                  try
                  {
                      $url = "https://" + $applianceIP + $uri

                      if($AppendUri)
                      {
                          $url = $url + "/" + $AppendUri
                      }

                      $respWeb = (Invoke-WebRequest -Uri $url -Method GET -Headers $header).Content
                      $resp = (New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($respWeb)

                     if($resp.ContainsKey('members'))
                     {
                        $resp.members = $resp.members.foreach({$_.Add("parentUri",$uri)})
                        $data.members += $resp.members
                        $data.count += $resp.count
                     }
                     else
                     {
                        $resp.Add("parentUri", $uri)                       
                        $data.members += $resp
                        $data.count += 1
                     }
                  }
                  catch
                  {
                    Continue
                  }
                }

				$jsonResp = $data | ConvertTo-Json -Depth 99

			}
			catch
			{
                Write-Host "StatusCode: " + $_.Exception.Response.StatusCode.value__
                Write-Host "StatusDescription: " + $_.Exception.Response.StatusDescription

                #$jsonResp = "StatusCode: " + $_.Exception.Response.StatusCode.value__ + "`nStatusDescription: " + $_.Exception.Response.StatusDescription
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


function extract_few_more_details()
{

    extract_data_by_uri -ResourceName "SAS-Storage" -FileName "sas-logical-drive-enclosures.txt" -RestRequest "/rest/sas-logical-jbods" -SearchParameter "logicalDriveBayUris" -UriLength 4
    extract_data_by_uri -ResourceName "ID-Pools" -FileName "ipv4-ranges.txt" -RestRequest "/rest/id-pools/ipv4/subnets" -SearchParameter "rangeUris" -UriLength 0
    extract_data_by_uri -ResourceName "ID-Pools" -FileName "ipv6-ranges.txt" -RestRequest "/rest/id-pools/ipv6/subnets" -SearchParameter "rangeUris" -UriLength 0       # added in v2.0
    extract_data_by_uri -ResourceName "ID-Pools" -FileName "vmac-ranges.txt" -RestRequest "/rest/id-pools/vmac" -SearchParameter "rangeUris" -UriLength 0
    extract_data_by_uri -ResourceName "ID-Pools" -FileName "vsn-ranges.txt" -RestRequest "/rest/id-pools/vsn" -SearchParameter "rangeUris" -UriLength 0
    extract_data_by_uri -ResourceName "ID-Pools" -FileName "vwwn-ranges.txt" -RestRequest "/rest/id-pools/vwwn" -SearchParameter "rangeUris" -UriLength 0
    extract_data_by_uri -ResourceName "Service-Automation" -FileName "remote-support-details.txt" -RestRequest "/rest/support/entitlements" -SearchParameter "hwuri" -UriLength 0      # v1.7

    # Extract additional Server Details
    $uri_list = extract_resource_uri_list -RestUri "/rest/server-hardware" -SearchField "uri" -UriLength 0

    $resource_set = @(
        ('memory',                    'server-hardware-memory.txt'),
        ('memoryList',                'server-hardware-memory-list.txt'),
        ('localStorage',              'server-hardware-local-storage.txt'),
        ('localStorageV2',            'server-hardware-local-storageV2.txt'),   # v2.1
        ('devices',                   'server-hardware-devices.txt'),
        ('bios',                      'server-hardware-bios.txt'),
        ('environmentalConfiguration','server-hardware-environmental-config.txt'),
        ('advancedMemoryProtection',  'server-hardware-advanced-memory-prot.txt')
        # ('utilization',               'server-hardware-utilization.txt')
        )

    foreach($resource in $resource_set)
    {
        extract_data_by_uri_list -ResourceName "Servers" -FileName $resource[1] -UriList $uri_list -AppendUri $resource[0]
    }

    # Extract additional SAS Details
    $uri_list = extract_resource_uri_list -RestUri "/rest/sas-logical-jbods" -SearchField "uri" -UriLength 0

    $resource = @('drives',  'sas-logical-jbods-drives.txt')
    extract_data_by_uri_list -ResourceName "SAS-Storage" -FileName $resource[1] -UriList $uri_list -AppendUri $resource[0]


    # Extract additional Storage Details
    $uri_list = extract_resource_uri_list -RestUri "/rest/storage-volumes" -SearchField "uri" -UriLength 0

    $resource = @('snapshots',  'storage-volumes-snapshots.txt')
    extract_data_by_uri_list -ResourceName "Storage" -FileName $resource[1] -UriList $uri_list -AppendUri $resource[0]

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

        #Extract Additional Information
        Write-Host "Extracting few more details....... " -NoNewline

        extract_few_more_details

        Write-Host "Done"

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
					$currentTime = Get-Date -Format "yyyyMMdd.HHmmss".toString()
					$archiveName = "syconf-" + $applianceIP + "-" + $currentTime + ".zip"
					$archivePath = Join-Path $scriptDir $archiveName

                    if(Test-Path $archivePath){
	                     Remove-Item -Path $archivePath
                    }
                    try
                    {
                        Invoke-Command -ScriptBlock {[System.IO.Compression.ZipFile]::CreateFromDirectory($resultDir, $archivePath)} | Wait-Job
                        Remove-Item -Path $resultDir -Recurse
                        Write-Host "`nOutput saved to:"
                        Write-Host "Path: " $scriptDir
                        Write-Host "File: " $archiveName
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
    Write-Host "List of IP 'iplist.txt' found:"

    foreach($ip in (Get-Content $iplistPath))
    {
        Write-Host("   $ip")
    }
    Write-Host "`nPlease enter credentials.`n"

    $username = Read-Host "Login"
    [SecureString]$password = Read-Host -AsSecureString "Password"
    $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

    foreach($ip in (Get-Content $iplistPath))
    {
        if($ip.length -gt 2)
        {
            $header = @{}

            extract_all -applianceIP $ip -Login $username -Password $decryptPassword

            Write-Host "`n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
        }
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

# Cleanup variables
$username = ""
$password.Clear()
$decryptPassword = ""

Read-Host "Press <Enter> to exit..."
