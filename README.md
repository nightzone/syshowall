syshowall
=========
`HPE Synergy Configuration Collector`

### Features:
* Collects HPE OneView or Global Dashboard Appliance configuration.
* Identifies latest supported API version for Appliance and collects data based on it.
* Collects output to ZIP archive.
* Supports:
   	-  HPE OneView Synergy Appliance
   	-  HPE OneView Appliance
   	-  HPE OneView Global Dashboard 

### Usage:
* Run `syshowall.ps1` or `syshowall_core.ps1`  
	- Save, Clone or Copy correspondent script file to your Windows PC
	- Run PowerShell for `syshowall.ps1` or PowerShell Core 7.0 or higher for `syshowall_core.ps1`
	- Run script 

* Enter required parameters:
	- Appliance IP:&emsp;IP-address or hostname of Synergy Appliance
	- Login:&emsp;&emsp;&emsp;&emsp;login user name in format domain\user or user
	- Password:&emsp;&emsp;user password

* Find collected configuration ZIP archive `syconf/gdconf-<ip_address>-<time_stamp>.zip` in script directory.

* Provide ZIP archive to HPE representative for further analysis.

Example of usage `syshowall.ps1`:
```
PS C:\Temp\syshowall> .\syshowall.ps1
syshowall v3.3 PS - Synergy Configuration Collector

Appliance IP: 10.72.14.39
Login: Administrator
Password: ********
```

Example of usage `syshowall_core.ps1`:
```
PS C:\Temp\syshowall> .\syshowall_core.ps1
syshowall v3.3 PS Core - Synergy Configuration Collector

Appliance IP: 10.72.14.39

PowerShell credential request
Appliance credentials
User: Administrator
Password for user Administrator: ********
```

For multiple appliances:
- Create `iplist.txt` in script directory and put single Appliance IP per line.
- All appliances must have same user credentials with at least Read only role for All resources.

Example of `iplist.txt`:

	192.168.0.4
	10.10.10.2

### Requirements:

For `syshowall.ps1`:  
* Microsoft .NET 4.5 installed
* Tested on Windows 10 and PowerShell 5.1
* Tested on Windows Server 2022 and PowerShell 5.1
* Tested on Windows Server 2012 R2 and PowerShell 4.0

For `syshowall_core.ps1`:  
* PowerShell Core version 7.0 and higher
* Tested on PowerShell 7.5

### Author:
Sergii Oleshchenko<br/>
