syshowall
=========
syshowall v3.0 PS - Synergy Configuration Collector

### Features:
* Collects HPE OneView or Global Dashboard Appliance configuration.
* Identifies latest supported API version for Appliance and collects data based on it.
* Collects output to syconf/gdconf-<ip_address>-<time_stamp>.zip archive.
* Supports:
   	-  HPE OneView Synergy Appliance
   	-  HPE OneView Appliance
   	-  HPE OneView Global Dashboard 

### Usage:
* Run syshowall.ps1
	- Save or Copy syshowall.ps1 script to your Windows PC
	- Right click on script and select Run with PowerShell
* Enter required parameters:
	- Appliance IP:    IP-address or hostname of Synergy Appliance
	- Login:           login user name in format domain\user or user
	- Password:        user password
* Find collected configuration zip archive "syconf-<ip_address>-<time_stamp>.zip" in script directory.
* Possible to use list of appliances. Just create iplist.txt in script directory and put single Appliance IP per line.

### Requirements:
* Microsoft .NET 4.5 installed
* Tested on Windows 10 and PowerShell 5.1
* Tested on Windows Server 2012 R2 and PowerShell 4.0

### Author:
Sergii Oleshchenko<br/>
Feedback to: sergii.oleshchenko@hpe.ua<br/>
