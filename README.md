
# OS X Auditor

OS X Auditor is a free Mac OS X computer forensics tool.

It does parse and hash the following artifacts on the running system or a copy of a system you want to analyze:
 * the kernel extensions
 * the system agents and daemons
 * the third parties' agents and daemons
 * the users' agents
 * the users' downloaded files
 * the users' quarantined files
 * the users' Safari history, downloads, topsites, databases and HTML5 localstore
 * the users' Firefox cookies, downloads, formhistory, permissions, places and  signons

It can verify the reputation of each file on Team Cymru MHR, VirusTotal, Malware.lu and your own local database

The results are rendered as a simple txt log or a HTML log

## Author

@Jipe_ / jipedevs at gmail


## How to install

Just copy all files from github

## Dependencies

 * pip install plistlib 
 * pip install plist

These dependencies will be removed when a working native plist python module will be available

## How to run

OS X Auditor runs well with python 2.7. It does not run with a different version of python yet (due to the plist nightmare)

python osxauditor.py -h

## License

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.

Bootstrap comes with its own license, see http://twitter.github.io/bootstrap/