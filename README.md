# OS X Auditor

OS X Auditor is a free Mac OS X computer forensics tool.

OS X Auditor parses and hashes the following artifacts on the running system or a copy of a system you want to analyze:
 * the kernel extensions
 * the system agents and daemons
 * the third party's agents and daemons
 * the old and deprecated system and third party's startup items
 * the users' agents
 * the users' downloaded files
 * the installed applications

It extracts:
 * the users' quarantined files
 * the users' Safari history, downloads, topsites, HTML5 databases and localstore
 * the users' Firefox cookies, downloads, formhistory, permissions, places and signons
 * the users' Chrome history and archives history, cookies, login data, top sites, web data, HTML5 databases and local storage
 * the users' social and email accounts
 * the WiFi access points the audited system has been connected to (and tries to geolocate them)

It also looks for suspicious keywords in the .plist themselves.
 
It can verify the reputation of each file on:
 * Team Cymru's MHR 
 * VirusTotal
 * Malware.lu
 * your own local database

It can aggregate all logs from the following directories into a zipball:
 * /var/log (-> /private/var/log)
 * /Library/logs
 * the user's ~/Library/logs

Finally, the results can be:
 * rendered as a simple txt log file (so you can cat-pipe-grep in them… or just grep)
 * rendered as a HTML log file
 * sent to a Syslog server

## Author

Jean-Philippe Teissier - @Jipe_ 

## How to install

Just copy all files from github

## Dependencies

If you plan to run OS X Auditor on a Mac, you will get a full plist parsing support with the OS X Foundation through pyobjc:
 * pip install pyobjc 

If you can't install pyobjc or if you plan to run OS X Auditor on another OS than Mac OS X, you may experience some troubles with the plist parsing:
 * pip install biplist
 * pip install plist

These dependencies will be removed when a working native plist module will be available in python

## How to run

OS X Auditor runs well with python >= 2.7.2. It does not run with a different version of python yet (due to the plist nightmare)

python osxauditor.py -h

## Changelog

### 0.3.1
 * NEW: provides with the system name, version and build of the audited system
 * NEW: ability to analyze installed Applications (-i/--installedapps)
 * NEW: extracts the Archived History from Google Chrome artifacts 
 * NEW: a human readable HTML log report :)
 * FIX: HTMLLog() and SYSLOGLog() now handle exceptions
 * FIX: ParsePackagesDir() is now recursive and only tries to parse apps or kernel extensions. Some DEBUG output added as well
 * FIX: HUGE UTF-8/UNICODE improvement
 * FIX: .DS_Store and .localized files are ignored in ParsePackagesDir() 

### 0.3
 * NEW: ability to parse Google Chrome artifacts (History and archives history, Cookies, Login Data, Top Sites, Web Data, HTML5 databases and local storage) with -b/--browsers
 * NEW: ability to extract the Wi-Fi APs the audited system has been connected to from the Airport Preferences and tries to geolocate them using Geomena (-A/--airportprefs). You must use -g/--wifiapgeolocate to enable the geolocation (or set GEOLOCATE_WIFI_AP to True in the code).
 * NEW: ability to extract users' social and email accounts (-U/--usersaccounts)
 * FIX: ability to handle the locked sqlite databases especially while auditing a live system
 * FIX: hashes duplicates removed
 * FIX: better identify md5 in the HTML output
 * CHANGE: indicates if a section (Startup items, Packages directory, Db tables, etc…) is empty to clarify the output
 * CHANGE: the downloads artifacts (-d/--downloads) include the old and new Mail.app default download directories
 
### 0.2.1
 * CHANGE/FIX: implement a BigFileMd5() function to hash very big files, avoid MemoryError execptions and reduce the memory footprint
 * FIX: UTF-8 entries from LSQuarantineEvent in ParseQuarantines()

### 0.2 
 * NEW: ability to send the results to a remote syslogd server (-S)
 * NEW: ability to create a zipball of all the log files found on the audited system (-z)
 * CHANGE: the analysis of startup artifacts includes the old and deprecated StartupItems
 * CHANGE: the analysis of startup artifacts includes the ScriptingAdditions
 * CHANGE: the analysis of quarantined artifact includes the old QuarantineEvents for Mac OS X systems <= 10.6
 * CHANGE: great improvement of plist hangling using the Python ⟷ Objective-C bridge (PyObjC) and OS X Foundation
 * CHANGE: some changes in the options parameters (-t, -l)
 * CHANGE: license changed from CC to GPL
 * CHANGE: debug levels are now more consitent in the output logs
 * CHANGE: a small change with the Bootstrap CSS 
 * CHANGE: the VirusTotal lookup is now done in a bulk mode
 * FIX: a bug in ParseLaunchAgents() on plist files containing both Program and ProgramArguments keys

### 0.1
 * Initial Release

## TODO
 * Google Chrome 'Protocol Buffers' and SNSS artifacts
 * Safari LastSession.plist
 * extract events from logs

## License

OS X Auditor
Copyright (C) 2013 Jean-Philippe Teissier

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Bootstrap and JQuery have their own GPL compatible licence.