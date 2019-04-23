# syshowall
Synergy configuration collector
version 1.2

Prerequisites:
* Microsoft Visual C++ 2015 Redistributable required to run application
	Download:  https://www.microsoft.com/en-US/download/details.aspx?id=52685 

Features:
* Identify latest supported API version for Synergy Appliance and collect data based on it.
* Collects syshowall output to .\Result folder.
* To achieve best result use Synergy Explorer v1.2 to parse collected data.

Usage:
* Run syshowall_v1.2.exe
* Enter required parameters:
	- Appliance IP:		IP-address or hostname of Synergy Appliance
	- User:			user name in format domain\user or user
	- Password:		user password (hidden chars)
* Find output in .\Result folder. Rename it to avoid overwrite with next program run.

Author:
* Sergii Oleshchenko
* Sophela, Kyiv, Ukraine
* Feedback by mail: sergii.oleshchenko@sophela.com


