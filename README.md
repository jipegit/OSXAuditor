# OS X Auditor

OS X Auditor is a free Mac OS X computer forensics tool.

It does parse and hash the following artifacts on the running system or a copy of a system you want to analyze:
 * the kernel extensions
 * the system agents and daemons
 * the third parties' agents and daemons
 * the old and deprecated system and third parties' startup items
 * the users' agents
 * the users' downloaded files
 * the users' quarantined files
 * the users' Safari history, downloads, topsites, databases and HTML5 localstore
 * the users' Firefox cookies, downloads, formhistory, permissions, places and  signons

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

If you plan to run OS X Auditor on a Mac. You will get a full plist parsing support:
 * pip install pyobjc 

If you can't install pyobjc or if you plan to run OS X Auditor on another OS than Mac OS X (You may experience some troubles with the plist parsing):
 * pip install biplist
 * pip install plist

These dependencies will be removed when a working native plist module will be available in python

## How to run

OS X Auditor runs well with python >= 2.7.2. It does not run with a different version of python yet (due to the plist nightmare)

python osxauditor.py -h

## Changelog

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
 * Google Chrome artifacts
 * Analysis of the Sandbox (/private/var/db/launchd.db)
 * Remove hashes duplicates
 
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

Bootstrap have its own GPL compatible licence.