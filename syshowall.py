'''
Syshowall v1.2.1 utility collects config from Synergy/OneView appliance.
Developed by Sergii Oleshchenko
mail: sergii.oleshchenko@sophela.com

'''

import requests
import json
import pathlib
import shutil
from getpass import getpass
#import time

global ipaddr
global login
global password
global headers
global folder

def GetXAPIversion(ipaddr):
    headers = {'Content-Type':'application/json'}
    resturl = '/rest/version'

    url = 'https://' + ipaddr + resturl
    xapi = 0
    try:
        response = requests.get(url,headers=headers,verify=False,timeout=10)
        jsonresp = json.loads(response.text)

        if response.status_code == 200 :
            xapi = jsonresp['currentVersion']
    except:
       pass
    return xapi

def ExtractData(resourceName,resourceREST):

    print("Extracting " + resourceName + ' data.......', end = ' ', flush = True)

    for rest in resourceREST :
        pathlib.Path(folder + resourceName).mkdir(parents=True,exist_ok=True)
        #print(rest)
        fileName = folder + resourceName + "\\" + resourceName + "_" + rest.split("/")[-1] + ".txt"
        #print(fileName)
        url = 'https://' + ipaddr + rest   # + '?start=0&count=4'
        response = requests.get(url,headers=headers,verify=False)
        if response.status_code == 200 :
            try:
                data = response.json()
                if 'count' in data :
                    counter = 0
                    while (data['nextPageUri'] != None and counter < 1000 and data['count'] < data['total']) :
                        counter += 1
                        url = 'https://' + ipaddr + data['nextPageUri']
                        #print(data['nextPageUri'])
                        response = requests.get(url,headers=headers,verify=False)
                        if response.status_code == 200 :
                                data1 = response.json()
                                data['members'].extend(data1['members'])
                                data['count'] += data1['count']
                                data['nextPageUri'] = data1['nextPageUri']

                with open(fileName,"w", encoding='UTF-16LE') as f:
                    json.dump(data, f, indent=4,ensure_ascii=False)
            except:
                with open(fileName,"w", encoding='UTF-16LE') as f:
                    f.write(response.text)
                pass
    print('Done')

# disable insecure warnings for https connections
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

# Appliance URI
restappliance = (
            "/rest/appliance/configuration/time-locale",               # added to collect Time settings on the appliance
            "/rest/appliance/device-read-community-string",
            "/rest/appliance/eula/status",        # attention
            "/rest/appliance/firmware/notification", # attention
            "/rest/appliance/firmware/pending",  # attention
            "/rest/appliance/firmware/verificationKey",
            "/rest/appliance/ha-nodes",                                # added to collect active/standby composer
            "/rest/appliance/health-status",
            "/rest/appliance/network-interfaces",
			"/rest/appliance/network-interfaces/mac-addresses",
            "/rest/appliance/notifications/email-config",
			"/rest/appliance/notifications/test-email-config",
            "/rest/appliance/progress",
            "/rest/appliance/settings/serviceaccess", # attention
            "/rest/appliance/trap-destinations",
            "/rest/backups",
			"/rest/backups/config",
            "/rest/deployment-servers/image-streamer-appliances",       # added to collect IS appliance details
            "/rest/domains",
            "/rest/domains/schema",
            "/rest/firmware-drivers",
            "/rest/global-settings",
			"/rest/index/filters",
            "/rest/licenses",
			"/rest/remote-syslog",
            "/rest/restores",
			"/rest/scopes",
            "/rest/version"
)

#HP OneView Version
resthponeviewver = (
        "/rest/appliance/nodeinfo/version",
)

# FC-SANS
restfcsans = (
        "/rest/fc-sans/device-managers",
        "/rest/fc-sans/managed-sans",
        "/rest/fc-sans/providers"
)

# Security
restsecurity = (
        "/rest/active-user-sessions",
        "/rest/authz/category-actions",
        "/rest/certificates/ca",
        "/rest/certificates/client/rabbitmq",
        "/rest/certificates",
        "/rest/logindomains",
        "/rest/logindomains/global-settings",
        "/rest/logindomains/grouptorolemapping",
        "/rest/roles",
        "/rest/sessions",
        "/rest/users",
        "/rest/certificates/https"
)

#Activity
#restactivity = (
#		"/rest/alerts",
#		"/rest/audit-logs",
#		"/rest/events",
#		"/rest/reports"
#		"/rest/tasks"
#)

#Servers
restservers = (
		"/rest/connections",
		"/rest/id-pools",
		"/rest/id-pools/vmac",
		"/rest/id-pools/vsn",
		"/rest/id-pools/vwwn",
		"/rest/server-hardware",
		"/rest/server-hardware-types",
		"/rest/server-profiles",
		"/rest/server-profile-templates",
		"/rest/server-hardware/*/firmware"                    # added to collect server FW details
)

#Enclosures
restenclosures= (
		"/rest/logical-enclosures",
		"/rest/enclosure-groups",
		"/rest/enclosures"
		)

#Networking
restnetworking = (
		"/rest/connection-templates",
		"/rest/ethernet-networks",
		"/rest/fc-networks",
		"/rest/interconnect-types",
		"/rest/interconnects",
		"/rest/logical-downlinks",
		"/rest/logical-interconnect-groups",
		"/rest/logical-interconnects",
		"/rest/network-sets",
		"/rest/switches",
		"/rest/uplink-sets",
		"/rest/internal-link-sets",
		"/rest/fabrics",
		"/rest/interconnect-link-topologies",
		"/rest/connections"
)

#Storage
reststorage = (
		"/rest/storage-systems",
		"/rest/storage-pools",
		"/rest/storage-volumes",
		"/rest/storage-volume-templates",
		"/rest/storage-volume-attachments",
		"/rest/fc-sans/device-managers"
)

#Facilities
restfacilities = (
		"/rest/datacenters",
		"/rest/power-devices",
		"/rest/racks"
)

#Uncategorized
restuncategorized = (
		"/rest/migratable-vc-domains",
		"/rest/unmanaged-devices"
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
restsas = (
	"/rest/sas-interconnect-types",
	"/rest/sas-interconnects",
	"/rest/sas-logicalterconnect-groups",
	"/rest/sas-logical-interconnect-groups",
	"/rest/sas-logical-interconnects",
	"/rest/drive-enclosures",
	"/rest/sas-logical-jbod-attachments",
	"/rest/sas-logical-jbods"
	)

# Service Automation
restsa = (
"/rest/support/channel-partners",
"/rest/support/configuration",
"/rest/support/contacts",
"/rest/support/datacenters",
"/rest/support/data-collections",
"/rest/support/data-collections/download",
"/rest/support/enclosures",
"/rest/support/portal-registration",
"/rest/support/registration",
"/rest/support/schedules",
"/rest/support/server-hardware",
"/rest/support/sites"
)

# id-pools
restidpools = (
"/rest/id-pools/ipv4/ranges/schema",
"/rest/id-pools/ipv4/subnets",
"/rest/id-pools/ipv4/ranges",
"/rest/id-pools/vmac/ranges",
"/rest/id-pools/vsn/ranges",
"/rest/id-pools/vwwn/ranges"
)


ipaddr =    '10.72.14.13'
login =     'Administrator'
password =  'P@ssw0rd'

headers = {
    'Accept-Language': 'en-US',
    'Content-Type': 'application/json',
    'X-Api-Version': '200'
}

sessionid = None
folder = "./Result/"

print('Syshowall v1.2.1 collects Synergy configuration.')

while sessionid == None :
    print()
    ipaddr =    input('Appliance IP: ')
    login =     input('Login: ')
#    password =  input('Password: ')
    password = getpass('Password: ')
    print()
    body = {
        "password":     password,
        "userName":     login,
        "loginMsgAck":  "true"
    }

    # check if result folder exists and remove it
    if pathlib.Path(folder).exists() and pathlib.Path(folder).is_dir() :
        try:
            path = pathlib.Path(folder).absolute()
            shutil.rmtree(path)
        except:
            print('Cannot remove Result folder. Trying to continue.')
            print()

    # identify X-Api version
    xapi = GetXAPIversion(ipaddr)
    if xapi != 0 :
        headers["X-Api-Version"] = str(xapi)
        print('Connectivity check...... ' + ipaddr + ' ....... Pass.')

        # check if domain user entered
        if login.find("\\") > 0 :
            body['authLoginDomain']=login.split('\\')[0]
            body['userName']=login.split('\\')[1]

        # create connection session
        url = 'https://' + ipaddr + '/rest/login-sessions'
        sessionid = None
        try:
            response = requests.post(url,headers=headers,json=body,verify=False)
            # Add sessionID to header
            if response.status_code == 200 :
                sessionid = json.loads(response.text)["sessionID"]
                headers["Auth"]=sessionid
                print('Connected successfully.')
            else:
                print('Login failed.\nPlease check credentials.\n')
                input('Press enter to continue...')
        except:
            print('Authentication error.')
            input('Press enter to continue...')
    else :
        print('Connectivity check...... '+ ipaddr + ' ....... Fail.\nCheck IP settings and network connectivity to Synergy Appliance.\n')
        input('Press enter to continue...')

print()

if sessionid != None :
    print('>> Extracting Data <<')

    ExtractData("Appliance",restappliance)
    ExtractData("HP-OneView-Version",resthponeviewver)
    ExtractData("FC-SAN",restfcsans)
    ExtractData("Security",restsecurity)
    ####ExtractData("Activity",restactivity)
    ExtractData("Servers",restservers)
    ExtractData("Enclosures",restenclosures)
    ExtractData("Networking",restnetworking)
    ExtractData("Storage",reststorage)
    ExtractData("Facilities",restfacilities)
    ExtractData("Uncategorized",restuncategorized)
    ####ExtractData("Index",index)
    ExtractData("SAS-Storage",restsas)
    ExtractData("Service-Automation",restsa)
    ExtractData("ID-Pools",restidpools)

    response = requests.delete(url,headers=headers,verify=False)
    if response.status_code == 204 :
        print()
        print('Disconnect from Appliance: ' + ipaddr)

input('Press enter to close window...')
