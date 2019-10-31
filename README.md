syshowall
=========
syshowall v1.4 PS - Synergy Configuration Collector

### Features:
* Collects HPE Synergy Appliance configuration.
* Identifies latest supported API version for Synergy Appliance and collects data based on it.
* Collects syshowall output to syconf-<ip_address>-<date_time>.zip archive.

### Usage:
* Run syshowall.ps1
* Enter required parameters:
	- Appliance IP:    IP-address or hostname of Synergy Appliance
	- Login:           login user name in format domain\user or user
	- Password:        user password 
* Find collected configuration zip archive "syconf-<ip_address>-<date_time>.zip" in script directory.
* Tested on Windows 10 and PowerShell 5.1

### Author:
Sergii Oleshchenko<br/>
Feedback to: sergii.oleshchenko@sophela.com<br/>
