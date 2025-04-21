syshowall
=========
`syshowall v4.0 PS - Synergy Configuration Collector`

### Features:
* Collects HPE OneView or Global Dashboard Appliance configuration.
* Identifies latest supported API version for Appliance and collects data based on it.
* Collects output to ZIP archive.
* Supports:
   	-  HPE OneView Synergy Appliance
   	-  HPE OneView Appliance
   	-  HPE OneView Global Dashboard 

### Usage:
* Run `syshowall.ps1`
	- Save, Clone or Copy `syshowall.ps1` script to your Windows PC
	- Run PowerShell Core 7.0 or higher
	- Run script 

* Enter required parameters:
	- Appliance IP:&emsp;IP-address or hostname of Synergy Appliance
	- Login:&emsp;&emsp;&emsp;&emsp;login user name in format domain\user or user
	- Password:&emsp;&emsp;user password

* Find collected configuration ZIP archive `syconf/gdconf-<ip_address>-<time_stamp>.zip` in script directory.

* Provide ZIP archive to HPE representative for further analysis.

Example:

	PS C:\Temp\syshowall> .\syshowall.ps1
	syshowall v4.0 PS - Synergy Configuration Collector

	Appliance IP: 10.72.14.39
	Login: Administrator
	Password: ********

For multiple appliances:
- Create `iplist.txt` in script directory and put single Appliance IP per line.
- All appliances must have same user credentials with at least Read only role for All resources.

Example of `iplist.txt`:

	192.168.0.4
	10.10.10.2

### Requirements:
* PowerShell Core version 7.0 and higher
* Tested on PowerShell 7.5

### Author:
Sergii Oleshchenko<br/>
