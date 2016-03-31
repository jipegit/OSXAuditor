#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
#  OS X Auditor
#
#  Author: Jean-Philippe Teissier ( @Jipe_ ) & al.
#
#  This work is licensed under the GNU General Public License
#

__description__ = 'OS X Auditor'
__author__ = '@Jipe_ & al.'
__version__ = '0.4.4'

ROOT_PATH = '/'
HOSTNAME = ''

HASHES = []
LOCAL_HASHES_DB = {}

HTML_LOG_FILE = False
HTML_LOG_CONTENT = u''
HTML_LOG_MENU = u''

HTML_EVENTS_TL = u''
HTML_EVENTS_LANES = []
HTML_EVENTS_ITEMS = u''

FOUNDATION_IS_IMPORTED = False
BIPLIST_IS_IMPORTED  = False
PLISTLIB_IS_IMPORTED = False

SYSLOG_SERVER = False
SYSLOG_PORT = 514                                               #You can change your SYSLOG port here

MRH_HOST = u'hash.cymru.com'
MRH_PORT = 43

GEOLOCATE_WIFI_AP = False
GEOMENA_API_HOST = u'http://geomena.org/ap/'

VT_HOST = u'https://www.virustotal.com/vtapi/v2/file/report'

ADMINS = []

OSX_VERSION = []

import sys
reload(sys)
sys.setdefaultencoding('UTF8')

import optparse
import os
import hashlib
import logging
from logging.handlers import SysLogHandler
import sqlite3
import socket
import time
import json
import zipfile
import codecs                                                   #binary plist parsing does not work well in python3.3 so we are stuck in 2.7 for now
from functools import partial
import re
import bz2
import binascii
import platform
import gzip

VT_API_KEY  = os.getenv('VT_API_KEY', False)

try:
    from urllib.request import urlopen                          #python3
except ImportError:
    import urllib, urllib2                                      #python2

try:
    import Foundation                                           #It only works on OS X
    FOUNDATION_IS_IMPORTED = True
    print(u'DEBUG: Mac OS X Obj-C Foundation successfully imported')
except ImportError:
    print(u'DEBUG: Cannot import Mac OS X Obj-C Foundation. Installing PyObjC on OS X is highly recommended')
    try:
        import biplist
        BIPLIST_IS_IMPORTED = True
    except ImportError:
        print(u'DEBUG: Cannot import the biplist lib. I may not be able to properly parse a binary pblist')
    try:
        import plistlib
        PLISTLIB_IS_IMPORTED = True
    except ImportError:
        print(u'DEBUG: Cannot import the plistlib lib. I may not be able to properly parse a binary pblist')

def HTMLLogFlush():
    ''' Flush the HTML report '''

    global HTML_LOG_CONTENT
    global HTML_LOG_MENU

    if HTML_LOG_FILE:
        HTML_LOG_HEADER = u"""<!DOCTYPE html>
                            <html lang=\"en\">
                            <head>
                            <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />
                            <title>OS X Auditor Report</title>
                            <link rel=\"stylesheet\" type=\"text/css\" href=\"bootstrap/css/bootstrap.min.css\">
                            <script type=\"text/javascript\" src=\"jquery/jquery-1.10.2.min.js\"></script>
                            <script type=\"text/javascript\" src=\"bootstrap/js/bootstrap.min.js\"></script>
                            <script type=\"text/javascript\" src=\"d3-3.2.8/d3.min.js\"></script>
                            <style type="text/css">
                            .chart {
                                shape-rendering: crispEdges;
                            }

                            .mini text {
                                font: 9px sans-serif;
                            }

                            .main text {
                                font: 12px sans-serif;
                            }

                            .miniItem0 {
                                fill: darksalmon;
                                stroke-width: 6;
                            }

                            .miniItem1 {
                                fill: darkolivegreen;
                                fill-opacity: .7;
                                stroke-width: 6;
                            }

                            .miniItem2 {
                                fill: slategray;
                                fill-opacity: .7;
                                stroke-width: 6;
                            }

                            .brush .extent {
                                stroke: gray;
                                fill: dodgerblue;
                                fill-opacity: .365;
                            }
                            </style>
                            </head>
                            <body data-spy=\"scroll\" data-target=\".navbar\" style=\"margin:0 20px 0 20px; padding-top:110px;\">
                            <div class=\"container\">
                                <div class=\"navbar navbar-inverse navbar-fixed-top\">
                                  <div class=\"navbar-inner\">
                                    <a class=\"brand\" href="#">OS X Auditor</a>
                                    <ul class=\"nav\">"""

        HTML_LOG_FOOTER = u'</body></html>'

        HTML_LOG_MENU = HTML_LOG_MENU[10:]
        HTML_LOG_MENU += '''</ul>
                            </div>
                            </div>
                            </div>'''

        HTML_LOG_FILE.write(HTML_LOG_HEADER)
        HTML_LOG_FILE.write(HTML_LOG_MENU)
        HTML_LOG_FILE.write(HTML_LOG_CONTENT)
        HTML_LOG_FILE.write(HTML_LOG_FOOTER)

        HTML_LOG_FILE.close()

def HTMLLog(LogStr, TYPE):
    ''' Write a string of HTML log depending of its type '''

    global HTML_LOG_CONTENT
    global HTML_LOG_MENU

    if TYPE == 'INFO':
        Splitted = LogStr.split(' ')
        if re.match('[A-Fa-f\d]{32}', Splitted[0]):                 #Should be a md5
            Link = u'<a href=\'https://www.virustotal.com/fr/file/' + Splitted[0] + u'/analysis/\'>' + Splitted[0] + u'</a> '
            HTML_LOG_CONTENT += u"<i class='icon-file'></i> " + Link + u" ".join(Splitted[1:]) + u"<br>"
        else:
            HTML_LOG_CONTENT += u"<i class='icon-file'></i> " + LogStr + u"<br>"

    elif TYPE == "INFO_RAW":
            HTML_LOG_CONTENT += u"<pre>" + LogStr + u"</pre><br>"

    elif TYPE == "WARNING":
        HTML_LOG_CONTENT += u"<div class=\"alert alert-error\"><i class='icon-fire'></i> "+ LogStr + u"</div>"

    elif TYPE == "ERROR":
        HTML_LOG_CONTENT += u"<div class=\"alert\"><i class='icon-warning-sign'></i> "+ LogStr + u"</div>"

    elif TYPE == "SECTION":
        HTML_LOG_CONTENT += u"<h2 id=\"" + LogStr + u"\">" + LogStr + u"</h2>"
        HTML_LOG_MENU += u"</ul></li><li class=\"dropdown\"><a href=\"#\" role=\"button\" class=\"dropdown-toggle\" data-toggle=\"dropdown\">" + LogStr + u"<b class=\"caret\"></b></a><ul class=\"dropdown-menu\">"
        HTML_LOG_MENU += u"<li role=\"presentation\"><a role=\"menuitem\" tabindex=\"-1\" href=\"#" + LogStr + u"\">" + LogStr + u"</a></li><li class=\"divider\"></li>"

    elif TYPE == "SUBSECTION":
        HTML_LOG_CONTENT += u"<h3 id=\"" + LogStr + u"\">" + LogStr + u"</h3>"
        HTML_LOG_MENU += u"<li role=\"presentation\"><a role=\"menuitem\" tabindex=\"-1\" href=\"#" + LogStr + u"\">" + LogStr + u"</a></li>"

    elif TYPE == "DEBUG":
        HTML_LOG_CONTENT += u"<i class='icon-wrench'></i> " + LogStr + u"<br>"

def SyslogSetup(SyslogServer):
    ''' Set the Syslog handler up'''

    global SYSLOG_SERVER

    try:
        Logger = logging.getLogger()
        Syslog = logging.handlers.SysLogHandler(address=(SyslogServer, SYSLOG_PORT))
        Formatter = logging.Formatter('OS X Auditor: ' + HOSTNAME + ' %(levelname)s: %(message)s')
        Syslog.setFormatter(Formatter)
        Logger.addHandler(Syslog)
        SYSLOG_SERVER = True
    except:
        PrintAndLog(u'Syslog setup failed, Syslog is disabled', 'ERROR')
        SYSLOG_SERVER = False

def PrintAndLog(LogStr, TYPE):
    ''' Write a string of log depending of its type and call the function to generate the HTML log or the Syslog if needed '''

    global HTML_LOG_FILE
    global SYSLOG_SERVER

    if TYPE == 'INFO' or 'INFO_RAW':
        print(u'[INFO] ' + LogStr)
        logging.info(LogStr)

    elif TYPE == 'ERROR':
        print(u'[ERROR] ' + LogStr)
        logging.error(LogStr)

    elif TYPE == 'WARNING':
        print(u'[WARNING] ' + LogStr)
        logging.warning(LogStr)

    elif TYPE == 'DEBUG':
        print(u'[DEBUG] ' + LogStr)
        logging.debug(LogStr)

    elif TYPE == 'SECTION' or TYPE == 'SUBSECTION':
        SectionTitle = u'\n#########################################################################################################\n'
        SectionTitle += '#                                                                                                       #\n'
        SectionTitle += '#         ' +LogStr+ ' '*(94-len(LogStr)) + '#\n'
        SectionTitle += '#                                                                                                       #\n'
        SectionTitle += '#########################################################################################################\n'
        print(SectionTitle)
        logging.info(u'\n' + SectionTitle)

    if HTML_LOG_FILE:
        HTMLLog(LogStr, TYPE)

def MHRLookup():
    ''' Perform of lookup in Team Cymru\'s MHR '''

    PrintAndLog(u'Team Cymru MHR lookup', 'SECTION')
    PrintAndLog(u'Got %s hashes to verify' % len(HASHES), 'DEBUG')

    Query = 'begin\r\n'
    for Hash in HASHES:
        Query += Hash + '\r\n'
    Query += 'end\r\n'

    S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    S.connect((MRH_HOST, MRH_PORT))
    S.sendall(Query)

    Response = u''
    while True:
        Data = S.recv(4096)
        Response += Data
        if not Data: break
    S.close()

    Lines = Response.split('\n')
    Lines = Lines[2:-1]

    for line in Lines:
        Status = line.split(' ')
        if Status[2] == 'NO_DATA':
            PrintAndLog(line.decode('utf-8'), 'INFO')
        else:
            PrintAndLog(line.decode('utf-8'), 'WARNING')

def VTLookup():
    ''' Perform of lookup in VirusTotal database '''

    PrintAndLog(u'Virustotal lookup', 'SECTION')
    PrintAndLog(u'Got %s hashes to verify' % len(HASHES), 'DEBUG')

    try:
        param = { 'resource': ','.join(HASHES), 'apikey': VT_API_KEY }
        data = urllib.urlencode(param)
        f = urllib2.urlopen(VT_HOST, data)
        data = f.read()

    except (urllib2.HTTPError, e):
        if e.code == 401:
            PrintAndLog(u'Wrong VirusTotal key', 'ERROR')
        else:
            PrintAndLog(u'VirusTotal error '+str(e.code)+' '+str(e.reason).decode('utf-8'), 'ERROR')

    Ret = json.loads(data)

    Results = []
    if type(Ret) is dict:
        Results.append(Ret)
    elif type(Ret) is list:
        Results = Ret

    for Entry in Results:
        if Entry['response_code'] == 1:
            if Entry['positives'] > 0:
                PrintAndLog(Entry['md5'] + u' ' + Entry['scan_date'] + u' ' + str(Entry['positives']) + u'/' + str(Entry['total']), 'WARNING')
            else:
                PrintAndLog(Entry['md5'] + u' '+ Entry['scan_date'] +' '+ str(Entry['positives']) + u'/' + str(Entry['total']), 'INFO')
        elif Entry['response_code'] == 0:
            PrintAndLog(Entry['resource'] + u' Never seen 0/0', 'INFO')
        else:
            PrintAndLog(u'Got a weird answer from Virustotal\n', 'ERROR')

def LocalLookup(HashDBPath):
    ''' Perform of lookup in a local database '''

    global LOCAL_HASHES_DB

    PrintAndLog(u'Local hashes DB lookup', 'SECTION')
    PrintAndLog(u'Got %s hashes to verify' % len(HASHES), 'DEBUG')

    with open(HashDBPath, 'r') as f:
        Data = f.readlines()
        for Line in Data:
            if Line[0] != '#':
                Line = Line.split(' ')
                LOCAL_HASHES_DB[Line[0]] = Line[1]

    PrintAndLog(str(len(LOCAL_HASHES_DB)) + u' hashes loaded from the local hashes database', 'DEBUG')

    for Hash in HASHES:
        if Hash in LOCAL_HASHES_DB:
            PrintAndLog(Hash + u' '+ LOCAL_HASHES_DB[Hash], 'WARNING')

def BigFileMd5(FilePath):
    ''' Return the md5 hash of a big file '''

    Md5 = hashlib.md5()
    try:
        with open(FilePath, 'rb') as f:
            for Chunk in iter(partial(f.read, 1048576), ''):
                Md5.update(Chunk)
            return Md5.hexdigest()
    except:
        PrintAndLog(u'Cannot hash ' + FilePath.decode('utf-8'), 'ERROR')
        return False

def UniversalReadPlist(PlistPath):
    ''' Try to read a plist depending of the plateform and the available libs. Good luck Jim... '''

    plistDictionary = False

    if FOUNDATION_IS_IMPORTED:
        plistNSData, errorMessage = Foundation.NSData.dataWithContentsOfFile_options_error_(PlistPath, Foundation.NSUncachedRead, None)
        if errorMessage is not None or plistNSData is None:
            PrintAndLog(u'Unable to read in the data from the plist file: ' + PlistPath.decode('utf-8'), 'ERROR')
        plistDictionary, plistFormat, errorMessage = Foundation.NSPropertyListSerialization.propertyListFromData_mutabilityOption_format_errorDescription_(plistNSData, Foundation.NSPropertyListMutableContainers, None, None)
        if errorMessage is not None or plistDictionary is None:
            PrintAndLog(u'Unable to read in the data from the plist file: ' + PlistPath.decode('utf-8'), 'ERROR')
        if not hasattr(plistDictionary, 'has_key'):
            PrintAndLog(u'The plist does not have a dictionary as its root as expected: ' + PlistPath.decode('utf-8'), 'ERROR')
        return plistDictionary
    else:
        if BIPLIST_IS_IMPORTED:
            try:
                plistDictionary = biplist.readPlist(PlistPath)
            except (IOError):
                PrintAndLog (u'Cannot open ' + PlistPath.decode('utf-8') , 'ERROR')
            except:
                PrintAndLog(u'Cannot parse ' + PlistPath.decode('utf-8') + u' (Binary or JSON plist may FAIL) \n', 'ERROR')
            return plistDictionary

        elif PLISTLIB_IS_IMPORTED:
            try:
                plistDictionary = plistlib.readPlist(PlistPath)
            except (IOError):
                PrintAndLog (u'Cannot open ' + PlistPath.decode('utf-8') , 'ERROR')
            except:
                PrintAndLog(u'Cannot parse ' + PlistPath.decode('utf-8') + u' (Binary or JSON plist may FAIL) \n', 'ERROR')
            return plistDictionary
        else:
            PrintAndLog(u'Cannot parse ' + PlistPath.decode('utf-8') + u'. No plist lib available.\n', 'ERROR')
            return None

def ParseQuarantines():
    ''' Parse users\' quarantines '''

    PrintAndLog(u'Quarantines', 'SECTION')

    for User in os.listdir(os.path.join(ROOT_PATH, 'Users/')):
        if User[0] != '.':
            PrintAndLog(User.decode('utf-8') +'\'s quarantine', 'SUBSECTION')
            DbPathV2 = os.path.join(ROOT_PATH, 'Users', User, 'Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2')        # OS X >= 10.7
            DbPathV1 = os.path.join(ROOT_PATH, 'Users', User, 'Library/Preferences/com.apple.LaunchServices.QuarantineEvents')          # OS X <= 10.6
            if os.path.isfile(DbPathV2):
                DbPath = DbPathV2
            elif os.path.isfile(DbPathV1):
                DbPath = DbPathV1
            else:
                PrintAndLog(u'No quarantined files for user ' + User.decode('utf-8') + u'\n', 'INFO')
                continue
            DbConnection = sqlite3.connect(DbPath)
            DbCursor = DbConnection.cursor()
            LSQuarantineEvents = DbCursor.execute('SELECT * from LSQuarantineEvent')
            for LSQuarantineEvent in LSQuarantineEvents:
                JointLSQuarantineEvent = u''
                for Q in LSQuarantineEvent:
                    decoded = str(Q).decode('UTF-8', 'ignore')
                    JointLSQuarantineEvent += u';' + decoded
                PrintAndLog(JointLSQuarantineEvent[1:] + u'\n'.decode('utf-8'), 'INFO')
            DbConnection.close()

def ParseStartupItems(StartupItemsPath):
    ''' Parse the StartupItems plist and hash its program argument '''

    StartupItemsPlist = False
    NbStartupItems = 0

    for StartupItems in os.listdir(StartupItemsPath):
        StartupItemsPlistPath = os.path.join(StartupItemsPath, StartupItems, 'StartupParameters.plist')

        PrintAndLog(StartupItemsPlistPath, 'DEBUG')
        StartupItemsPlist = UniversalReadPlist(StartupItemsPlistPath)

        if StartupItemsPlist:
            if 'Provides' in StartupItemsPlist:
                FilePath = os.path.join(StartupItemsPath, StartupItems, StartupItemsPlist['Provides'][0])
                Md5 = BigFileMd5(FilePath)
                if Md5:
                    if Md5 not in HASHES:
                        HASHES.append(Md5)
                    PrintAndLog(Md5 + u' '+ FilePath.decode('utf-8') + u' - ' + time.ctime(os.path.getmtime(FilePath)) + u' - ' + time.ctime(os.path.getctime(FilePath))+ u'\n', 'INFO')
        NbStartupItems += 1
    if NbStartupItems == 0:
        PrintAndLog(StartupItemsPath.decode('utf-8') + u' is empty', 'INFO')

def ParseLaunchAgents(AgentsPath):
    ''' Parse a LanchAgent plist and hash its program argument. Also look for suspicious keywords in the plist itself '''

    SuspiciousPlist = ['exec', 'socket' ,'open', 'connect', '/dev/tcp/', '/bin/sh']
    LaunchAgentPlist = False

    NbLaunchAgents = 0
    for LaunchAgent in os.listdir(AgentsPath):
        LaunchAgentPlistpath = os.path.join(AgentsPath, LaunchAgent)

        PrintAndLog(LaunchAgentPlistpath, 'DEBUG')
        LaunchAgentPlist = UniversalReadPlist(LaunchAgentPlistpath)

        if LaunchAgentPlist:
            if 'Program' in LaunchAgentPlist and 'Label' in LaunchAgentPlist:
                FilePath = LaunchAgentPlist['Program']
                Md5 = BigFileMd5(FilePath)
                if Md5:
                    if Md5 not in HASHES:
                        HASHES.append(Md5)
                    PrintAndLog(Md5 + u' '+ FilePath.decode('utf-8') + u' - ' + time.ctime(os.path.getmtime(FilePath)) + u' - ' + time.ctime(os.path.getctime(FilePath)) + u'\n', 'INFO')
                continue
            if 'ProgramArguments' in LaunchAgentPlist and 'Label' in LaunchAgentPlist:
                FilePath = LaunchAgentPlist['ProgramArguments'][0]
                Md5 = BigFileMd5(FilePath)
                if Md5:
                    if Md5 not in HASHES:
                        HASHES.append(Md5)
                    PrintAndLog(Md5 + u' '+ FilePath.decode('utf-8') + u' - ' + time.ctime(os.path.getctime(FilePath)) + u' - ' + time.ctime(os.path.getmtime(FilePath)) + u'\n', 'INFO')
                if len(LaunchAgentPlist['ProgramArguments']) >= 3:
                    if any(x in LaunchAgentPlist['ProgramArguments'][2] for x in SuspiciousPlist):
                        PrintAndLog(LaunchAgentPlist['ProgramArguments'][2].decode('utf-8')+ u' in ' + LaunchAgentPlistpath.decode('utf-8') + u' looks suspicious', 'WARNING')
        NbLaunchAgents += 1

    if NbLaunchAgents == 0:
        PrintAndLog(AgentsPath.decode('utf-8') + u' is empty', 'INFO')

def ParseStartup():
    ''' Parse the different LauchAgents and LaunchDaemons  '''

    PrintAndLog(u'Startup', 'SECTION')

    PrintAndLog(u'System agents', 'SUBSECTION')
    ParseLaunchAgents(os.path.join(ROOT_PATH, 'System/Library/LaunchAgents/'))

    PrintAndLog(u'System daemons', 'SUBSECTION')
    ParseLaunchAgents(os.path.join(ROOT_PATH, 'System/Library/LaunchDaemons/'))

    PrintAndLog(u'Third party agents', 'SUBSECTION')
    ParseLaunchAgents(os.path.join(ROOT_PATH, 'Library/LaunchAgents/'))

    PrintAndLog(u'Third party daemons', 'SUBSECTION')
    ParseLaunchAgents(os.path.join(ROOT_PATH, 'Library/LaunchDaemons/'))

    PrintAndLog(u'System ScriptingAdditions', 'SUBSECTION')
    ParsePackagesDir(os.path.join(ROOT_PATH, 'System/Library/ScriptingAdditions/'))

    PrintAndLog(u'Third party ScriptingAdditions', 'SUBSECTION')
    ParsePackagesDir(os.path.join(ROOT_PATH, 'Library/ScriptingAdditions/'))

    # Parse the old and deprecated Startup Items
    PrintAndLog(u'Deprecated system StartupItems', 'SUBSECTION')
    ParseStartupItems(os.path.join(ROOT_PATH, 'System/Library/StartupItems/'))

    PrintAndLog(u'Deprecated third party StartupItems', 'SUBSECTION')
    ParseStartupItems(os.path.join(ROOT_PATH, 'Library/StartupItems/'))

    PrintAndLog(u'Users\' agents', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        UserLAPath = os.path.join(ROOT_PATH, 'Users', User, 'Library/LaunchAgents/')
        if User[0] != '.' and os.path.isdir(UserLAPath):
            PrintAndLog(User.decode('utf-8') + u'\'s agents', 'SUBSECTION')
            ParseLaunchAgents(UserLAPath)

    PrintAndLog(u'Users\' LoginItems', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        LoginItemsPlistPath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Preferences/com.apple.loginitems.plist')
        if User[0] != '.' and os.path.isfile(LoginItemsPlistPath):
            PrintAndLog(User + u'\'s LoginItems', 'SUBSECTION')
            PrintAndLog(LoginItemsPlistPath, 'DEBUG')
            LoginItemsPlist = UniversalReadPlist(LoginItemsPlistPath)

            if LoginItemsPlist and 'SessionItems' in LoginItemsPlist:
                CustomListItems = LoginItemsPlist['SessionItems']['CustomListItems']
                for CustomListItem in CustomListItems:
                    PrintAndLog(CustomListItem['Name'].decode('utf-8') + u' - ' + binascii.hexlify(CustomListItem['Alias']).decode('hex').decode('utf-8', 'ignore'), 'INFO')

def HashDir(Title, Path):
    ''' Hash a direrctory and add the hashes'''
    PrintAndLog(Title.decode('utf-8'), 'SUBSECTION')

    NbFiles = 0
    for Root, Dirs, Files in os.walk(Path):
        for File in Files:
            FilePath = os.path.join(Root, File)
            Md5 = BigFileMd5(FilePath)
            if Md5:
                if Md5 not in HASHES:
                    HASHES.append(Md5)
                PrintAndLog(Md5 +' '+ FilePath.decode('utf-8') + u' - ' + time.ctime(os.path.getmtime(FilePath)) + u' - ' + time.ctime(os.path.getctime(FilePath)) + u'\n', 'INFO')
            NbFiles += 1

    if NbFiles == 0:
        PrintAndLog(Path.decode('utf-8') + u' is empty', 'INFO')

def ParseDownloads():
    ''' Hash all users\' downloaded files '''

    PrintAndLog(u'Users\' downloads', 'SECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        if User[0] != '.':
            DlUserPath = os.path.join(ROOT_PATH, 'Users', User, 'Downloads')
            if os.path.isdir(DlUserPath):
                HashDir(User + u'\'s downloads', DlUserPath)
            else:
                PrintAndLog(DlUserPath + u' does not exist', 'DEBUG')
            OldEmailUserPath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Mail Downloads/')
            if os.path.isdir(OldEmailUserPath):
                HashDir(User + u'\'s old email downloads', OldEmailUserPath)
            else:
                PrintAndLog(OldEmailUserPath + u' does not exist', 'DEBUG')
            EmailUserPath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Containers/com.apple.mail/Data/Library/Mail Downloads')
            if os.path.isdir(EmailUserPath):
                HashDir(User + u'\'s email downloads', EmailUserPath)
            else:
                PrintAndLog(EmailUserPath + u' does not exist', 'DEBUG')

def DumpSQLiteDb(SQLiteDbPath):
    ''' Dump a SQLite database file '''

    PrintAndLog(SQLiteDbPath, 'DEBUG')
    if os.path.isfile(SQLiteDbPath):
        try:
            DbConnection = sqlite3.connect(SQLiteDbPath)
            DbCursor = DbConnection.cursor()
            DbCursor.execute("SELECT * from sqlite_master WHERE type = 'table'")
            Tables =  DbCursor.fetchall()
            for Table in Tables:
                PrintAndLog(u'Table ' + Table[2].decode('utf-8'), 'DEBUG')
                DbCursor.execute("SELECT * from " + Table[2])
                Rows = DbCursor.fetchall()
                if len(Rows) == 0:
                    PrintAndLog(u'Table ' + Table[2].decode('utf-8') + u' is empty', 'INFO')
                else:
                    for Row in Rows:
                        PrintAndLog(str(Row).decode('utf-8') + u'\n', 'INFO_RAW')
            DbConnection.close()
        except Exception as e:
            PrintAndLog(u'Error with ' + SQLiteDbPath.decode('utf-8') + u': ' + str(e.args).decode('utf-8'), 'ERROR')
    else:
        PrintAndLog(SQLiteDbPath.decode('utf-8') + u' not found\n', 'ERROR')

def ParseFirefoxProfile(User, Profile):
    ''' Parse the different SQLite databases in a Firefox profile '''

    PrintAndLog(User + u'\'s Firefox profile (' + Profile.decode('utf-8') + u')', 'SUBSECTION')

    #Most useful See http://kb.mozillazine.org/Profile_folder_-_Firefox
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'cookies.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'downloads.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'formhistory.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'places.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'signons.sqlite'))

    #Secondary
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'permissions.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'addons.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'extensions.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'content-prefs.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'healthreport.sqlite'))
    DumpSQLiteDb(os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles/', Profile, 'webappsstore.sqlite'))

def ParseFirefox():
    ''' Walk in all users' FireFox profiles and call ParseFirefoxProfile() '''

    PrintAndLog(u'Users\' Firefox profiles', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        UserFFProfilePath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Firefox/Profiles')
        if User[0] != '.' and os.path.isdir(UserFFProfilePath):
            PrintAndLog(User + u'\'s Firefox', 'SUBSECTION')
            for Profile in os.listdir(UserFFProfilePath):
                if Profile[0] != '.' and os.path.isdir(os.path.join(UserFFProfilePath,  Profile)):
                    ParseFirefoxProfile(User, Profile)

def ParseSafariProfile(User, Path):
    ''' Parse the different plist and SQLite databases in a Safari profile '''

    HistoryPlist = False
    DownloadsPlist = False
    NbFiles = 0

    PrintAndLog(User + u'\'s Safari profile', 'SUBSECTION')

    PrintAndLog(User + u'\'s Safari downloads', 'SUBSECTION')
    DownloadsPlistPath = os.path.join(Path, 'Downloads.plist')
    PrintAndLog(DownloadsPlistPath.decode('utf-8'), 'DEBUG')

    DownloadsPlist = UniversalReadPlist(DownloadsPlistPath)

    if DownloadsPlist:
        if 'DownloadHistory' in DownloadsPlist:
            Downloads = DownloadsPlist['DownloadHistory']
            for DL in Downloads:
                DlStr = u''
                DlStr += DL['DownloadEntryURL'].decode('utf-8') + u' -> ' + DL['DownloadEntryPath'].decode('utf-8') + u' (' + DL['DownloadEntryIdentifier'].decode('utf-8') + u')\n'
                PrintAndLog(DlStr, 'INFO')

    PrintAndLog(User + u'\'s Safari history', 'SUBSECTION')
    HistoryPlistPath = os.path.join(Path, 'History.plist')
    PrintAndLog(HistoryPlistPath.decode('utf-8'), 'DEBUG')

    HistoryPlist = UniversalReadPlist(HistoryPlistPath)

    if HistoryPlist:
        if 'WebHistoryDates' in HistoryPlist:
            History =  HistoryPlist['WebHistoryDates']
            for H in History:
                HStr = u''
                if 'title' in H:
                    HStr += unicode(H['title']) + u' - '
                if 'diplayTitle' in H:
                    HStr += unicode(H['diplayTitle']) + u' - '
                HStr += unicode(H['']) + u'\n'
                PrintAndLog(HStr, 'INFO')

    PrintAndLog(User + u'\'s Safari TopSites', 'SUBSECTION')
    TopSitesPlistPath = os.path.join(Path, 'TopSites.plist')

    PrintAndLog(TopSitesPlistPath.decode('utf-8'), 'DEBUG')
    TopSitesPlist = UniversalReadPlist(TopSitesPlistPath)

    if TopSitesPlist:
        if 'TopSites' in TopSitesPlist:
            TopSites =  TopSitesPlist['TopSites']
            for T in TopSites:
                TStr = u''
                if 'TopSiteTitle' in T:
                    TStr += unicode(T['TopSiteTitle']) + u' - '
                TStr += unicode(T['TopSiteURLString']) + u'\n'
                PrintAndLog(TStr , 'INFO')


    PrintAndLog(User + u'\'s Safari LastSession', 'SUBSECTION')
    LastSessionPlistPath = os.path.join(Path, 'LastSession.plist')

    PrintAndLog(LastSessionPlistPath.decode('utf-8'), 'DEBUG')
    LastSessionPlist = UniversalReadPlist(LastSessionPlistPath)

    if LastSessionPlist and 'SessionWindows' in LastSessionPlist:
        try:
            SessionWindows = LastSessionPlist['SessionWindows']
            if len(SessionWindows) > 0:
                TabStates = SessionWindows[0].get('TabStates', [])
                if len(TabStates) > 0:
                    LastSession = TabStates[0]
                    PrintAndLog(LastSession.get('TabURL', '').decode('utf-8') + u' - ' + binascii.hexlify(LastSession['SessionState']).decode('hex').decode('utf-8', 'ignore'), 'INFO')
        except:
            PrintAndLog('EXCEPTION on LastSession for Safari !!! ', 'INFO')



    PrintAndLog(User + u'\'s Safari databases', 'SUBSECTION')
    NbFile = 0
    if os.path.isfile(os.path.join(Path, 'Databases')):
        for Db in os.listdir(os.path.join(Path, 'Databases')):
            DumpSQLiteDb(os.path.join(Path, 'Databases', Db))
            NbFiles += 1

    if  NbFiles == 0:
        PrintAndLog(User + u'\'s Safari databases is empty', 'INFO')

    NbFile = 0

    PrintAndLog(User + u'\'s Safari LocalStorage', 'SUBSECTION')
    if os.path.isfile(os.path.join(Path, 'LocalStorage')):
        for Db in os.listdir(os.path.join(Path, 'LocalStorage')):
	     if os.path.isfile(os.path.join(Path, 'LocalStorage', Db)):
                 DumpSQLiteDb(os.path.join(Path, 'LocalStorage', Db))
                 NbFiles += 1

    if  NbFiles == 0:
        PrintAndLog(User + u'\'s Safari LocalStorage is empty', 'INFO')

def ParseSafari():
    PrintAndLog(u'Users\' Safari profiles', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        UserSafariProfilePath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Safari')
        if User[0] != '.' and os.path.isdir(UserSafariProfilePath):
            ParseSafariProfile(User, UserSafariProfilePath)

def ParseChromeProfile(User, Path):
    ''' Parse the different SQLite databases in a Chrome profile '''

    NbFiles = 0

    PrintAndLog(User + u'\'s Chrome profile', 'SUBSECTION')

    PrintAndLog(User + u'\'s Chrome history', 'SUBSECTION')
    DumpSQLiteDb(os.path.join(Path, 'History'))

    PrintAndLog(User + u'\'s Chrome archived history', 'SUBSECTION')
    DumpSQLiteDb(os.path.join(Path, 'Archived History'))

    PrintAndLog(User + u'\'s Chrome cookies', 'SUBSECTION')
    DumpSQLiteDb(os.path.join(Path, 'Cookies'))

    PrintAndLog(User + u'\'s Chrome login data', 'SUBSECTION')
    DumpSQLiteDb(os.path.join(Path, 'Login Data'))

    PrintAndLog(User + u'\'s Chrome Top Sites', 'SUBSECTION')
    DumpSQLiteDb(os.path.join(Path, 'Top Sites'))

    PrintAndLog(User + u'\'s Chrome web data', 'SUBSECTION')
    DumpSQLiteDb(os.path.join(Path, 'Web Data'))

    PrintAndLog(User + u'\'s Chrome databases', 'SUBSECTION')
    for Db in os.listdir(os.path.join(Path, 'databases')):
        CurrentDbPath = os.path.join(Path, 'databases', Db)
        if CurrentDbPath[-8:] != '-journal' and not os.path.isdir(CurrentDbPath):
            DumpSQLiteDb(CurrentDbPath)
        NbFiles += 1

    if  NbFiles == 0:
        PrintAndLog(User + u'\'s Chrome databases is empty', 'INFO')

    NbFiles = 0

    PrintAndLog(User + u'\'s Chrome LocalStorage', 'SUBSECTION')
    for Db in os.listdir(os.path.join(Path, 'Local Storage')):
        CurrentDbPath = os.path.join(Path, 'Local Storage', Db)
        if CurrentDbPath[-8:] != '-journal' and not os.path.isdir(CurrentDbPath):
            DumpSQLiteDb(CurrentDbPath)
        NbFiles += 1

    if  NbFiles == 0:
        PrintAndLog(User + u'\'s Chrome LocalStorage is empty', 'INFO')

def ParseChrome():
    ''' Parse the different files in a Chrome profile '''

    PrintAndLog(u'Users\' Chrome profiles', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        UsersChromePath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Application Support/Google/Chrome/Default')
        if User[0] != '.' and os.path.isdir(UsersChromePath):
            ParseChromeProfile(User, UsersChromePath)

def ParseBrowsers():
    ''' Call the different functions to parse the browsers   '''

    PrintAndLog(u'Browsers', 'SECTION')

    ParseSafari()
    ParseFirefox()
    ParseChrome()

def ParsePackagesDir(PackagesDirPath):
    ''' Parse the packages in a directory '''

    plistfile = 'Info.plist'
    IgnoredFiles = ['.DS_Store', '.localized']

    PackagePlistPath = ''
    CFBundleExecutablepath = ''
    NbPackages = 0

    for PackagePath in os.listdir(PackagesDirPath):
        if PackagePath not in IgnoredFiles:
            if PackagePath[-4:] == '.app' or PackagePath[-5:] == '.kext':
                if os.path.isfile(os.path.join(PackagesDirPath, PackagePath, plistfile)):
                    PackagePlistPath = os.path.join(PackagesDirPath, PackagePath, plistfile)
                    CFBundleExecutablepath = ''
                elif os.path.isfile(os.path.join(PackagesDirPath, PackagePath, 'Contents', plistfile)):
                    PackagePlistPath = os.path.join(PackagesDirPath, PackagePath, 'Contents', plistfile)
                    CFBundleExecutablepath = 'Contents/MacOS/'
                else:
                    PrintAndLog(os.path.join(PackagesDirPath, PackagePath).decode('utf-8'), 'DEBUG')
                    PrintAndLog(u'Cannot find any Info.plist in ' + PackagePath.decode('utf-8'), 'ERROR')
                    continue

                PrintAndLog(os.path.join(PackagesDirPath, PackagePath).decode('utf-8'), 'DEBUG')
                PackagePlist = UniversalReadPlist(PackagePlistPath)

                if PackagePlist:
                    if 'CFBundleExecutable' in PackagePlist:
                        if PackagePlist['CFBundleExecutable'] != '':
                            FilePath = os.path.join(PackagesDirPath, PackagePath, CFBundleExecutablepath, PackagePlist['CFBundleExecutable'])
                            Md5 = BigFileMd5(FilePath)
                            if Md5:
                                if Md5 not in HASHES:
                                    HASHES.append(Md5)
                                PrintAndLog(Md5 + u' '+ FilePath.decode('utf-8') + u' - ' + time.ctime(os.path.getmtime(FilePath)) + u' - ' + time.ctime(os.path.getctime(FilePath)) + u'\n', 'INFO')
                        else:
                            PrintAndLog(u'The CFBundleExecutable key in ' + PackagePlistPath.decode('utf-8') + u' is empty\n', 'ERROR')
                    else:
                        PrintAndLog(u'Cannot find the CFBundleExecutable key in ' + PackagePlistPath.decode('utf-8') + u'\n', 'ERROR')
            NbPackages += 1

            if os.path.isdir(os.path.join(PackagesDirPath, PackagePath)) and not os.path.islink(os.path.join(PackagesDirPath, PackagePath)):
                ParsePackagesDir(os.path.join(PackagesDirPath, PackagePath))

        else: continue

    if NbPackages == 0:
        PrintAndLog(PackagesDirPath.decode('utf-8') + u' is empty (no package found)', 'INFO')

def ParseKext():
    ''' Parse the Kernel extensions '''

    PrintAndLog(u'Kernel extensions', 'SECTION')
    ParsePackagesDir(os.path.join(ROOT_PATH, 'System/Library/Extensions/'))

def AggregateLogsDir(ZipHandle, LogDirPath):
    ''' Aggregate all logs found in a directory to a zipball '''

    NbLogFiles = 0

    for Root, Dirs, Files in os.walk(LogDirPath):
        for File in Files:
            FilePath = os.path.join(Root, File)
            try:
                ZipHandle.write(FilePath)
                PrintAndLog(u'Log file ' + FilePath.decode('utf-8') + u' added to the logs zipball', 'INFO')
            except:
                PrintAndLog(FilePath.decode('utf-8') + u' aggregation FAILED', 'ERROR')
            NbLogFiles += 1

    if NbLogFiles == 0:
            PrintAndLog(LogDirPath.decode('utf-8') + u' is empty', 'INFO')

def AggregateLogs(ZipLogsFile):
    ''' Walk in the different log directories to add all logs to a zipball '''

    PrintAndLog(u'Log files aggregation', 'SECTION')
    
    if not os.path.isdir(ZipLogsFile):
        os.makedirs(ZipLogsFile)

    ZipLogsFilePath = os.path.join(ZipLogsFile, 'OSXAuditor_report_' + HOSTNAME + '_' + time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '.zip')
    PrintAndLog(u'All log files are aggregated in ' + ZipLogsFilePath.decode('utf-8'), 'DEBUG')

    try:
        with zipfile.ZipFile(ZipLogsFilePath, 'w') as ZipLogsFile:
            PrintAndLog(os.path.join(ROOT_PATH, 'var/log').decode('utf-8') + u' files aggregation', 'SUBSECTION')
            AggregateLogsDir(ZipLogsFile, os.path.join(ROOT_PATH, 'var/log'))
            PrintAndLog(os.path.join(ROOT_PATH, 'Library/logs').decode('utf-8') + u' files aggregation', 'SUBSECTION')
            AggregateLogsDir(ZipLogsFile, os.path.join(ROOT_PATH, 'Library/logs'))
            for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
                if User[0] != '.':
                    PrintAndLog(os.path.join(ROOT_PATH, 'Users', User, 'Library/logs').decode('utf-8') + u' files aggregation', 'SUBSECTION')
                    AggregateLogsDir(ZipLogsFile, os.path.join(ROOT_PATH, 'Users', User, 'Library/logs'))
    except Exception as e:
        PrintAndLog(u'Log files aggregation FAILED ' + str(e.args).decode('utf-8'), 'ERROR')

def GeomenaApiLocation(Ssid):
    ''' Perform a geolocation query on Geomena'''

    NormalizedSsid = ''
    Latitude = 'Not found'
    Longitude = 'Not found'

    Ssid = Ssid.split(':')

    for i in Ssid:
        if len(i) == 1:
            i = '0'+i
        NormalizedSsid += i

    PrintAndLog(u'Geomena query for ' + ''.join(NormalizedSsid), 'DEBUG')

    try:
        F = urllib2.urlopen(GEOMENA_API_HOST + NormalizedSsid)
        Data = F.read()
    except urllib2.HTTPError as e:
        PrintAndLog(u'Geomena API error ' + str(e.code) + ' ' + str(e.reason).decode('utf-8'), 'ERROR')

    M = re.match('.+\sLatitude:\s([-\d\.]{1,19})\s.+\sLongitude:\s([-\d\.]{1,19})\s.+', Data, re.DOTALL)
    if M:
        Latitude = M.group(1)
        Longitude = M.group(2)

    return u'Latitude: ' + Latitude + u' Longitude: ' + Longitude

def ParseAirportPrefs():
    ''' Parse Airport preferences and try to extract geolocation information '''

    global HTML_LOG_FILE
    AirportPrefPlist = False
    NbAirportPrefs = 0

    PrintAndLog(u'Airport preferences', 'SECTION')

    AirportPrefPlistPath = os.path.join(ROOT_PATH, 'Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist')

    PrintAndLog(AirportPrefPlistPath, 'DEBUG')
    AirportPrefPlist = UniversalReadPlist(AirportPrefPlistPath)

    if AirportPrefPlist:
        if 'KnownNetworks' in AirportPrefPlist:
            KnownNetworks = AirportPrefPlist['KnownNetworks']
            for KnownNetwork in KnownNetworks:              #TODO: Add ChannelHistory
                if GEOLOCATE_WIFI_AP:
                    Geolocation = GeomenaApiLocation(KnownNetworks[KnownNetwork]['SSIDString'])
                else:
                    Geolocation = 'N/A (Geolocation disabled)'
                
                print sys.getsizeof(KnownNetworks[KnownNetwork]['SSID'])
                AirportPref = u'SSID: ' + KnownNetworks[KnownNetwork]['SSIDString'].decode('utf-8') + u' - SSID: ' + str(KnownNetworks[KnownNetwork]['SSID'])
                
                if KnownNetworks[KnownNetwork]['LastConnected']:
                    AirportPref = AirportPref + u' - Last connected: '+ str(KnownNetworks[KnownNetwork]['LastConnected'])
                
                AirportPref = AirportPref + u' - Security type: ' + KnownNetworks[KnownNetwork]['SecurityType'] + u' - Geolocation: ' + Geolocation
                
                PrintAndLog(AirportPref, 'INFO')
                NbAirportPrefs += 1

    if NbAirportPrefs == 0:
        PrintAndLog(AirportPrefPlistPath + u' is empty (no WiFi AP saved)', 'INFO')

def ParseMailAppAccount(MailAccountPlistPath):
    ''' Parse a Mail Account plist '''

    MailAccountPlist = False
    NbMailAccounts = 0
    NbSmtpAccounts = 0

    PrintAndLog(MailAccountPlistPath, 'DEBUG')

    MailAccountPlist = UniversalReadPlist(MailAccountPlistPath)

    if MailAccountPlist:
        PrintAndLog(u'Email accounts', 'SUBSECTION')
        if 'MailAccounts' in MailAccountPlist:
            MailAccounts = MailAccountPlist['MailAccounts']
            for MailAccount in MailAccounts:
                MAccountPref = ''
                if 'AccountName' in MailAccount:
                    MAccountPref = 'AccountName: ' + MailAccount['AccountName'] + ' - '
                    if 'AccountType' in MailAccount: MAccountPref += 'AccountType: ' + MailAccount['AccountType'] + ' - '
                    if 'SSLEnabled' in MailAccount: MAccountPref += 'SSLEnabled: ' + MailAccount['SSLEnabled'] + ' - '
                    if 'Username' in MailAccount: MAccountPref += 'Username: ' + MailAccount['Username']  + ' - '
                    if 'Hostname' in MailAccount: MAccountPref += 'Hostname: ' + MailAccount['Hostname']  + ' - '
                    if 'PortNumber' in MailAccount: MAccountPref += '(' + str(MailAccount['PortNumber'])  + ') - '
                    if 'SMTPIdentifier' in MailAccount: MAccountPref += 'SMTPIdentifier: ' + MailAccount['SMTPIdentifier']  + ' - '
                    if 'EmailAddresses' in MailAccount:
                        for EmailAddresse in MailAccount['EmailAddresses']:
                            MAccountPref += 'EmailAddresse: ' + EmailAddresse + ' - '
                    PrintAndLog(MAccountPref.decode('utf-8'), 'INFO')
                NbMailAccounts += 1
            if NbMailAccounts == 0:
                PrintAndLog(u'No email account)','INFO')

        PrintAndLog(u'SMTP accounts', 'SUBSECTION')
        if 'DeliveryAccounts' in MailAccountPlist:
            DeliveryAccounts = MailAccountPlist['DeliveryAccounts']
            for DeliveryAccount in DeliveryAccounts:
                DAccountPref = ''
                if 'AccountName' in DeliveryAccount:
                    DAccountPref = 'AccountName: ' + DeliveryAccount['AccountName'] + ' - '
                    if 'AccountType' in DeliveryAccount: DAccountPref += 'AccountType: ' + DeliveryAccount['AccountType'] + ' - '
                    if 'SSLEnabled' in DeliveryAccount: DAccountPref += 'SSLEnabled: ' + DeliveryAccount['SSLEnabled'] + ' - '
                    if 'Username' in DeliveryAccount: DAccountPref += 'Username: ' + DeliveryAccount['Username']  + ' - '
                    if 'Hostname' in DeliveryAccount: DAccountPref += 'Hostname: ' + DeliveryAccount['Hostname']  + ' - '
                    if 'PortNumber' in DeliveryAccount: DAccountPref += '(' + str(DeliveryAccount['PortNumber'])  + ') - '
                    PrintAndLog(DAccountPref.decode('utf-8'), 'INFO')
                NbSmtpAccounts += 1
            if NbSmtpAccounts == 0:
                PrintAndLog(u'No SMTP account)','INFO')

def ParseUsersRecentItems(RecentItemsAccountPlistPath):
    ''' Parse users' recents items'''

    PrintAndLog(RecentItemsAccountPlistPath, 'DEBUG')

    RecentItemsAccountPlist = UniversalReadPlist(RecentItemsAccountPlistPath)

    if RecentItemsAccountPlist:
        if 'RecentServers' in RecentItemsAccountPlist:
            RecentServersList = ''
            RecentServers = RecentItemsAccountPlist['RecentServers']['CustomListItems']
            if len(RecentServers) != 0:
                for RecentServer in RecentServers:
                    RecentServersList += RecentServer['Name'] + ' -> ' #+ RecentServer['URL']
                PrintAndLog('Recent servers : ' + RecentServersList, 'INFO')
            else:
                PrintAndLog('No recent servers', 'INFO')

        if 'RecentDocuments' in RecentItemsAccountPlist:
            RecentDocumentsList = ''
            RecentDocuments = RecentItemsAccountPlist['RecentDocuments']['CustomListItems']
            if len(RecentDocuments) != 0:
                for RecentDocument in RecentDocuments:
                    RecentDocumentsList += RecentDocument['Name']
                PrintAndLog('Recent documents : ' + RecentDocumentsList, 'INFO')
            else:
                PrintAndLog('No recent documents', 'INFO')

        if 'RecentApplications' in RecentItemsAccountPlist:
            RecentApplicationsList = ''
            RecentApplications = RecentItemsAccountPlist['RecentApplications']['CustomListItems']
            if len(RecentApplications) != 0:
                for RecentApplication in RecentApplications:
                    RecentApplicationsList += RecentApplication['Name']
                PrintAndLog('Recent Applications : ' + RecentApplicationsList, 'INFO')
            else:
                PrintAndLog('No recent applications', 'INFO')

        if 'Hosts' in RecentItemsAccountPlist:
            RecentHostsList = ''
            RecentHosts = RecentItemsAccountPlist['Hosts']['CustomListItems']
            if len(RecentHosts) != 0:
                for RecentHost in RecentHosts:
                    RecentHostsList += RecentHost['Name'] + ' -> ' + RecentHost['URL'] + ' | '
                PrintAndLog('Recent hosts : ' + RecentHostsList, 'INFO')
            else:
                PrintAndLog('No recent hosts', 'INFO')

def StringFromDic(dic):
    ''' Return the content of a dictionary '''

    Content = u''
    for stuff in dic:
        Content += stuff + u'\n'
    return Content


def ParseSysUsers():
    ''' Parse the system users db '''

    global ADMINS

    PrintAndLog(u'System\'s users', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'private/var/db/dslocal/nodes/Default/users')):
        if User[0] != '.':
            SysUserPlistPath = os.path.join(ROOT_PATH, 'private/var/db/dslocal/nodes/Default/users', User)
            PrintAndLog(User[:-6] + u'\'s system account details', 'SUBSECTION')

            SysUserPlist = UniversalReadPlist(SysUserPlistPath)

            UserDetails =''
            if SysUserPlist:
                if 'name' in SysUserPlist:
                    Names = u''
                    for Name in SysUserPlist['name']:
                        Names += Name
                        if Name in ADMINS:
                            Names += u' (is Admin)'
                        Names += u'\n'
                    UserDetails += u'Name(s): ' + Names

                if 'realname' in SysUserPlist:
                    UserDetails += u'Real Name(s): ' + StringFromDic(SysUserPlist['realname'])

                if 'shell' in SysUserPlist:
                    UserDetails += u'Shell(s): ' + StringFromDic(SysUserPlist['shell'])

                if 'home' in SysUserPlist:
                    UserDetails += u'Home(s): ' + StringFromDic(SysUserPlist['home'])

                if 'uid' in SysUserPlist:
                    UserDetails += u'UID(s): ' + StringFromDic(SysUserPlist['uid'])

                if 'gid' in SysUserPlist:
                    UserDetails += u'GID(s): ' + StringFromDic(SysUserPlist['gid'])

                if 'generateduid' in SysUserPlist:
                    Generateduids = u''
                    for Generateduid in SysUserPlist['generateduid']:
                        Generateduids += Generateduid
                        if Generateduid in ADMINS:
                            Generateduids += u' (is Admin)'
                        Generateduids += u'\n'
                    UserDetails += u'generated UID(s): ' + Generateduids

                if 'LinkedIdentity' in SysUserPlist:
                    UserDetails += u'LinkedIdentities have been found. Extraction of LinkedIdentities is not implemented yet.'

                PrintAndLog(UserDetails, 'INFO_RAW')

def ParseSysAdminsGroup():
    ''' Parse the system admins group db '''

    global ADMINS

    PrintAndLog(u'System\'s admins', 'SUBSECTION')

    SysAdminsPlistPath = os.path.join(ROOT_PATH, 'private/var/db/dslocal/nodes/Default/groups/admin.plist')
    SysAdminsPlist = UniversalReadPlist(SysAdminsPlistPath)

    if SysAdminsPlist:
        if 'groupmembers' in SysAdminsPlist:
            for Admin in SysAdminsPlist['groupmembers']:
                ADMINS.append(Admin)

        if 'users' in SysAdminsPlist:
            for Admin in SysAdminsPlist['users']:
                ADMINS.append(Admin)

        Admins = u''
        for Admin in ADMINS:
            Admins += Admin + u'\n'
        PrintAndLog(Admins, 'INFO_RAW')

def ParseUsersAccounts():
    ''' Parse users' accounts '''

    PrintAndLog(u'Users\' accounts', 'SECTION')

    PrintAndLog(u'Users\' social accounts', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        UsersAccountPath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Accounts/Accounts3.sqlite')
        if User[0] != '.':
            PrintAndLog(User + u'\'s social account', 'SUBSECTION')
            if os.path.isfile(UsersAccountPath):
                DumpSQLiteDb(UsersAccountPath)
            else:
                PrintAndLog(User + u' has no social account', 'INFO')

    PrintAndLog(u'Users\' Mail.app accounts', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        MailAccountPlistPath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Containers/com.apple.mail/Data/Library/Mail/V2/MailData/Accounts.plist')
        if User[0] != '.':
            PrintAndLog(User + u'\'s Mail.app accounts', 'SUBSECTION')
            if os.path.isfile(MailAccountPlistPath):
                ParseMailAppAccount(MailAccountPlistPath)
            else:
                PrintAndLog(User + u' has no Mail.app account', 'INFO')

    PrintAndLog(u'Users\' recent items', 'SUBSECTION')
    for User in os.listdir(os.path.join(ROOT_PATH, 'Users')):
        RecentItemsAccountPlistPath = os.path.join(ROOT_PATH, 'Users', User, 'Library/Preferences/com.apple.recentitems.plist')
        if User[0] != '.':
            PrintAndLog(User + u'\'s recent items', 'SUBSECTION')
            if os.path.isfile(RecentItemsAccountPlistPath):
                ParseUsersRecentItems(RecentItemsAccountPlistPath)
            else:
                PrintAndLog(User + u' has no recent items', 'INFO')

    ParseSysAdminsGroup()
    ParseSysUsers()

def ParseInstalledApps():
    ''' Parses and hashes installed apps in /Applications '''

    PrintAndLog(u'Installed applications', 'SECTION')
    ParsePackagesDir(os.path.join(ROOT_PATH, 'Applications'))

def GetAuditedSystemVersion():
    ''' Simply return the system version '''

    global OSX_VERSION

    SysVersion = 'Unknown system version'
    SystemVersionPlist = False

    SystemVersionPlist = UniversalReadPlist('/System/Library/CoreServices/SystemVersion.plist')

    if SystemVersionPlist:
        if 'ProductName' in SystemVersionPlist: SysVersion = SystemVersionPlist['ProductName']
        if 'ProductVersion' in SystemVersionPlist: SysVersion += ' ' + SystemVersionPlist['ProductVersion']
        if 'ProductBuildVersion' in SystemVersionPlist: SysVersion += ' build ' + SystemVersionPlist['ProductBuildVersion']

        ProductVersion = SystemVersionPlist['ProductVersion'].split('.')

        OSX_VERSION = {
			'ProductBuildVersion': SystemVersionPlist['ProductBuildVersion'],
			'ProductVersion': SystemVersionPlist['ProductVersion'],
			'MajorVersion': int(ProductVersion[0]),
			'MinorVersion': int(ProductVersion[1]),
			'PatchVersion': int(ProductVersion[2] if len(ProductVersion) > 2 else 0)
		}

    else:
        PrintAndLog(u'Cannot determine the system version', 'ERROR')

    return SysVersion


def GetAuditedSystemTimezone():
    ''' Return the current system timezone '''

    Timezone = False
    try:
        Timezone = os.path.realpath(os.path.join(ROOT_PATH, 'etc/localtime'))
        Timezone = Timezone.split('/')
    except Exception as e:
        PrintAndLog(u'Cannot read the timezone' + str(e.args).decode('utf-8'), 'ERROR')

    return Timezone[-2] + '/' + Timezone[-1]


def ParseSystemlogFile(SystemLogPath, Year, Bzip2ed=False, Gziped=False):
    ''' Extract events from a System.log file '''

    global HTML_EVENTS_LANES
    global HTML_EVENTS_ITEMS
    global HTML_EVENTS_LANES_CPT
    AllEvents = []
    SystemLogData = ''

    PrintAndLog(SystemLogPath, 'DEBUG')

    if Gziped:
        try:
            with gzip.open(SystemLogPath, 'rb') as SystemLogFile:
                SystemLogData = SystemLogFile.read()
        except:
            PrintAndLog('Failed to open ' + SystemLogPath.decode('utf-8'), 'ERROR')
    else:
        try:
            with open(SystemLogPath, 'r') as SystemLogFile:
                SystemLogData = SystemLogFile.read()
                if Bzip2ed: SystemLogData = bz2.decompress(SystemLogData)
        except:
            PrintAndLog('Failed to open ' + SystemLogPath.decode('utf-8'), 'ERROR')

    DateRegex = '^(?P<date>\w{3}\s{1,2}\d{1,2}\s[\d:]{8})'

    BootTimesRegExp = re.compile(DateRegex + '.+BOOT_TIME', re.MULTILINE)
    ShutDownTimesRegExp = re.compile(DateRegex + '.+\sSHUTDOWN_TIME', re.MULTILINE)

    HibernationInTimesLRegExp = re.compile(DateRegex + '.+\sPMScheduleWakeEventChooseBest', re.MULTILINE)       #Lion
    HibernationInTimesMLRegExp = re.compile(DateRegex + '.+\shibernate_setup\(0\)\stook', re.MULTILINE)     #Mountain Lion
    HibernationOutTimesLRegExp = re.compile(DateRegex + '.+\sMessage\sWake', re.MULTILINE)                      #Lion TOFIX (in SYSLOG)
    HibernationOutTimesMLRegExp = re.compile(DateRegex + '.+\sWake\sreason', re.MULTILINE)                      #Mountain Lion

    LockedSessionsLRegExp = re.compile(DateRegex + '.+\sloginwindow', re.MULTILINE)                         #Lion
    LockedSessionsMLRegExp = re.compile(DateRegex + '.+\sApplication\sApp:\'loginwindow\'', re.MULTILINE)       #Mountain Lion

    SessionsUnlockFailRegExp = re.compile(DateRegex + '.+\sThe\sauthtok\sis\sincorrect', re.MULTILINE)          #Lion and Mountain Lion
    SessionsUnlockOkRegExp = re.compile(DateRegex + '.+\Establishing\scredentials', re.MULTILINE)               #Lion and Mountain Lion

    SudosOkRegExp = re.compile(DateRegex + '.+\ssudo\[\d+\]:\s+(?P<sudo>.+)$', re.MULTILINE)            #Lion and Mountain Lion
    SudosFailRegExp = re.compile(DateRegex + '.+\sincorrect\spassword\sattempts', re.MULTILINE)             #Lion and Mountain Lion

    USBKernelRegExp = re.compile(DateRegex + '.+\sUSBMSC\sIdentifier.+:\s(?P<serial>[a-zA-Z0-9]+)\s', re.MULTILINE)                                         #Lion and Mountain Lion
    FsEventRegExp = re.compile(DateRegex + '.+\sfseventsd.+log\sdir:\s(?P<volume>/Volumes/.+)\.fseventsd getting\snew\suuid:\s(?P<uuid>.+)$', re.MULTILINE) #Lion and Mountain Lion

    HFSMountRegExp = re.compile(DateRegex + '.+\shfs:\smounted\s(?P<mountpoint>.+)$', re.MULTILINE)                                         #Lion and Mountain Lion

    TTYOpenedRegExp = re.compile(DateRegex + '.+\sUSER_PROCESS:\s\d+\sttys', re.MULTILINE)                      #Lion and Mountain Lion
    TTYClosedRegExp = re.compile(DateRegex + '.+\sDEAD_PROCESS:\s\d+\sttys', re.MULTILINE)                      #Lion and Mountain Lion

    NetUPKernelRegExp = re.compile(DateRegex + '.+\skernel\[\d\+]:\sEthernet.+Link\up', re.MULTILINE)           #Lion and Mountain Lion
    NetChangeLRegExp = re.compile(DateRegex + '.+\sconfigd\[\d+]:\snetwork\sconfiguration\schanged', re.MULTILINE)          #Lion
    NetChangeMLRegExp = re.compile(DateRegex + '.+\sconfigd\[\d+]:\snetwork\schanged:', re.MULTILINE)           #Mountain Lion

    BootTimes = BootTimesRegExp.findall(SystemLogData)
    for Item in BootTimes: AllEvents.append([Item, 'Boot', 1])

    ShutDownTimes = ShutDownTimesRegExp.findall(SystemLogData)
    for Item in ShutDownTimes: AllEvents.append([Item, 'Shutdown', 2])

    HibernationInTimesL = HibernationInTimesLRegExp.findall(SystemLogData)
    for Item in HibernationInTimesL: AllEvents.append([Item, 'Hibernation in', 3])

    HibernationInTimesML = HibernationInTimesMLRegExp.findall(SystemLogData)
    for Item in HibernationInTimesML: AllEvents.append([Item, 'Hibernation in', 3])

    HibernationOutTimesL = HibernationOutTimesLRegExp.findall(SystemLogData)
    for Item in HibernationOutTimesL: AllEvents.append([Item, 'Hibernation out', 4])

    HibernationOutTimesML = HibernationOutTimesMLRegExp.findall(SystemLogData)
    for Item in HibernationOutTimesML: AllEvents.append([Item, 'Hibernation out', 4])

    # LockedSessionsL = LockedSessionsLRegExp.findall(SystemLogData)
    # AllEvents.append([LockedSessionsL, 'Locked sessions', 5])

    # LockedSessionsML = LockedSessionsMLRegExp.findall(SystemLogData)
    # AllEvents.append([LockedSessionsML, 'Locked sessions', 5])

    SessionsUnlockFail = SessionsUnlockFailRegExp.findall(SystemLogData)
    for Item in SessionsUnlockFail: AllEvents.append([Item, 'Sessions unlock FAIL', 6])
    
    SessionsUnlockOk = SessionsUnlockOkRegExp.findall(SystemLogData)
    for Item in SessionsUnlockOk: AllEvents.append([Item, 'Sessions unlock OK', 7])

    SudosOk = SudosOkRegExp.findall(SystemLogData)
    for Item in SudosOk: AllEvents.append([Item[0], 'Sudo OK: ' + Item[1], 8])

    SudosFail = SudosFailRegExp.findall(SystemLogData)
    for Item in SudosFail: AllEvents.append([Item, 'Sudo FAIL', 9])

    USBsKernel = USBKernelRegExp.findall(SystemLogData)
    for Item in USBsKernel: AllEvents.append([Item[0], 'USB device (kernel) - serial: ' + Item[1], 10])
    
    FsEvents = FsEventRegExp.findall(SystemLogData)
    for Item in FsEvents: AllEvents.append([Item[0], 'Filesystem (fseventsd) - volume: ' + Item[1] + ' UUID: ' + Item[2], 11])

    TTYsOpened = TTYOpenedRegExp.findall(SystemLogData)
    for Item in TTYsOpened: AllEvents.append([Item, 'TTY opened', 12])

    TTYsClosed = TTYClosedRegExp.findall(SystemLogData)
    for Item in TTYsClosed: AllEvents.append([Item, 'TTY closed', 13])

    HFSMountEvents = HFSMountRegExp.findall(SystemLogData)
    for Item in HFSMountEvents: AllEvents.append([Item[0], 'HFS mount (kernel): volume ' + Item[1], 14])

    # NetsUPKernel = NetUPKernelRegExp.findall(SystemLogData)
    # AllEvents.append([NetsUPKernel, 'Network iface UP (kernel)', 14])

    # NetsChangeL = NetChangeLRegExp.findall(SystemLogData)
    # AllEvents.append([NetsChangeL, 'Network change', 15])

    # NetsChangeML = NetChangeMLRegExp.findall(SystemLogData)
    # AllEvents.append([NetsChangeML, 'Network change', 15])

    AllEvents.sort(key=lambda a:a[0])

    for Events in AllEvents:
        if Events[1] not in HTML_EVENTS_LANES:
            HTML_EVENTS_LANES.append(Events[1])
        SplittedTime = Events[0].split(' ')
        if len(SplittedTime) == 3:
            EventTimeWithYear = ' '.join(SplittedTime[0:2]) + ', ' + Year + ' ' + SplittedTime[2]
        elif len(SplittedTime) == 4:
            EventTimeWithYear = ' '.join(SplittedTime[0:3]) + ', ' + Year + ' ' + SplittedTime[3]
        else:
            PrintAndLog(u'Cannot parse a syslog date', 'ERROR')
            EventTimeWithYear = 'DateError'
        PrintAndLog(EventTimeWithYear + ' UTC: ' + Events[1] + '\n', 'INFO')
    #HTML_EVENTS_ITEMS += '{\'lane\': ' + str(Events[2]) + ', \'id\': \'' + EventTimeWithYear + '\', \'start\': \'' + EventTimeWithYear + '\', \'end\': \'' + EventTimeWithYear + '\'},\n'
    HTML_EVENTS_ITEMS += 'N/A yet'

def ParseEventLogs():
    ''' Extract events from the event logs '''

    global HTML_EVENTS_TL
    global HTML_LOG_CONTENT
    global HTML_EVENTS_LANES

    PrintAndLog('Event logs', 'SECTION')

    SystemLogsPath = os.path.join(ROOT_PATH, 'var/log/')

    PrintAndLog('System logs', 'SUBSECTION')

    for LogFile in os.listdir(SystemLogsPath):
        LogFilePath = os.path.join(SystemLogsPath, LogFile)
        Year = time.strftime('%Y', time.localtime(os.path.getctime(LogFilePath)))                                   #nasty hack because the syslog format sucks

        if re.match('^system\.log$', LogFile):
            ParseSystemlogFile(LogFilePath, Year)
        if re.match('^system\.log\.\d\.bz2$', LogFile):
            ParseSystemlogFile(LogFilePath, Year, Bzip2ed=True)
        if re.match('^system\.log\.\d\.gz$', LogFile):
            ParseSystemlogFile(LogFilePath, Year, Gziped=True)

    Lanes = '\', \''.join(HTML_EVENTS_LANES)

    HTML_EVENTS_TL += "<script type=\"text/javascript\">var lanes = [\"" + Lanes + "\"], laneLength = lanes.length, items = [" + HTML_EVENTS_ITEMS + "]"
    HTML_EVENTS_TL += """
                timeBegin = \"Jan 1, 2013 00:00:00\",
                timeEnd = \"Dec 31, 2013 23:59:59\";

                </script>
                <script type=\"text/javascript\">
                    var m = [20, 15, 15, 120], //top right bottom left
                        w = 4000 - m[1] - m[3],
                        h = 500 - m[0] - m[2],
                        miniHeight = laneLength * 12 + 50,
                        mainHeight = h - miniHeight - 50;

                    //var parseDate = d3.time.format(\"%Y-%m-%d %H:%M:%S\").parse; //2013-05-22 15:00:00
                    var parseDate = d3.time.format(\"%b %d, %Y %H:%M:%S\").parse; //Jun 13, 2013 20:07:09

                    //scales
                    var x = d3.scale.linear()
                            //.domain([timeBegin, timeEnd])
                            .domain([parseDate(timeBegin), parseDate(timeEnd)])
                            .range([0, w]);
                    var x1 = d3.scale.linear()
                            .range([0, w]);
                    var y1 = d3.scale.linear()
                            .domain([0, laneLength])
                            .range([0, mainHeight]);
                    var y2 = d3.scale.linear()
                            .domain([0, laneLength])
                            .range([0, miniHeight]);

                    var chart = d3.select(\"body\")
                                .append(\"svg\")
                                .attr(\"width\", w + m[1] + m[3])
                                .attr(\"height\", h + m[0] + m[2])
                                .attr(\"class\", \"chart\");

                    chart.append(\"defs\").append(\"clipPath\")
                        .attr(\"id\", \"clip\")
                        .append(\"rect\")
                        .attr(\"width\", w)
                        .attr(\"height\", mainHeight);

                    var main = chart.append(\"g\")
                                .attr(\"transform\", \"translate(\" + m[3] + \",\" + m[0] + \")\")
                                .attr(\"width\", w)
                                .attr(\"height\", mainHeight)
                                .attr(\"class\", \"main\");

                    var mini = chart.append(\"g\")
                                .attr(\"transform\", \"translate(\" + m[3] + \",\" + (mainHeight + m[0]) + \")\")
                                .attr(\"width\", w)
                                .attr(\"height\", miniHeight)
                                .attr(\"class\", \"mini\");

                    //main lanes and texts
                    main.append(\"g\").selectAll(\".laneLines\")
                        .data(items)
                        .enter().append(\"line\")
                        .attr(\"x1\", m[1])
                        .attr(\"y1\", function(d) {return y1(d.lane);})
                        .attr(\"x2\", w)
                        .attr(\"y2\", function(d) {return y1(d.lane);})
                        .attr(\"stroke\", \"lightgray\")

                    main.append(\"g\").selectAll(\".laneText\")
                        .data(lanes)
                        .enter().append(\"text\")
                        .text(function(d) {return d;})
                        .attr(\"x\", -m[1])
                        .attr(\"y\", function(d, i) {return y1(i + .5);})
                        .attr(\"dy\", \".5ex\")
                        .attr(\"text-anchor\", \"end\")
                        .attr(\"class\", \"laneText\");

                    //mini lanes and texts
                    mini.append(\"g\").selectAll(\".laneLines\")
                        .data(items)
                        .enter().append(\"line\")
                        .attr(\"x1\", m[1])
                        .attr(\"y1\", function(d) {return y2(d.lane);})
                        .attr(\"x2\", w)
                        .attr(\"y2\", function(d) {return y2(d.lane);})
                        .attr(\"stroke\", \"lightgray\");

                    mini.append(\"g\").selectAll(\".laneText\")
                        .data(lanes)
                        .enter().append(\"text\")
                        .text(function(d) {return d;})
                        .attr(\"x\", -m[1])
                        .attr(\"y\", function(d, i) {return y2(i + .5);})
                        .attr(\"dy\", \".5ex\")
                        .attr(\"text-anchor\", \"end\")
                        .attr(\"class\", \"laneText\");

                    var itemRects = main.append(\"g\")
                                        .attr(\"clip-path\", \"url(#clip)\");

                    //mini item rects
                    mini.append(\"g\").selectAll(\"miniItems\")
                        .data(items)
                        .enter().append(\"rect\")
                        .attr(\"class\", function(d) {return \"miniItem\" + d.lane;})
                        .attr(\"x\", function(d) {return x(parseDate(d.start));})
                        .attr(\"y\", function(d) {return y2(d.lane + .5) - 5;})
                        .attr(\"width\", function(d) {
                            return x(parseDate(d.end)) - x(parseDate(d.start));
                            })
                        .attr(\"height\", 10);

                    //mini labels
                    mini.append(\"g\").selectAll(\".miniLabels\")
                        .data(items)
                        .enter().append(\"text\")
                        .text(function(d) {return d.id;})
                        .attr(\"x\", function(d) {return x(parseDate(d.start));})
                        .attr(\"y\", function(d) {return y2(d.lane + .5);})
                        .attr(\"dy\", \".5ex\");

                    //brush
                    var brush = d3.svg.brush()
                                        .x(x)
                                        .on(\"brush\", display);

                    mini.append(\"g\")
                        .attr(\"class\", \"x brush\")
                        .call(brush)
                        .selectAll(\"rect\")
                        .attr(\"y\", 1)
                        .attr(\"height\", miniHeight - 1);

                    display();

                    function display() {
                        var rects, labels,
                            minExtent = brush.extent()[0],
                            maxExtent = brush.extent()[1],
                            visItems = items.filter(function(d) {
                                return parseDate(d.start) < maxExtent && parseDate(d.end) > minExtent;
                                });

                        mini.select(\".brush\")
                            .call(brush.extent([minExtent, maxExtent]));

                        x1.domain([minExtent, maxExtent]);

                        //update main item rects
                        rects = itemRects.selectAll(\"rect\")
                                .data(visItems, function(d) { return d.id; })
                            .attr(\"x\", function(d) {return x1(parseDate(d.start));})
                            .attr(\"width\", function(d) {return x1(parseDate(d.end)) - x1(parseDate(d.start));});

                        rects.enter().append(\"rect\")
                            .attr(\"class\", function(d) {return \"miniItem\" + d.lane;})
                            .attr(\"x\", function(d) {return x1(parseDate(d.start));})
                            .attr(\"y\", function(d) {return y1(d.lane) + 10;})
                            .attr(\"width\", function(d) {return x1(parseDate(d.end)) - x1(parseDate(d.start));})
                            .attr(\"height\", function(d) {return .8 * y1(1);});

                        rects.exit().remove();

                        //update the item labels
                        labels = itemRects.selectAll(\"text\")
                            .data(visItems, function (d) { return d.id; })
                            .attr(\"x\", function(d) {return x1(Math.max(parseDate(d.start), minExtent) + 2);});

                        labels.enter().append(\"text\")
                            .text(function(d) {return d.id;})
                            .attr(\"x\", function(d) {return x1(Math.max(parseDate(d.start), minExtent));})
                            .attr(\"y\", function(d) {return y1(d.lane + .5);})
                            .attr(\"text-anchor\", \"start\");

                        labels.exit().remove();
                    }
                    </script>
                    """

    if HTML_LOG_FILE:
        PrintAndLog('System logs timeline', 'SUBSECTION')
        HTML_LOG_CONTENT += HTML_EVENTS_TL

def Main():
    ''' Here we go '''

    global ROOT_PATH
    global HTML_LOG_FILE
    global HOSTNAME
    global GEOLOCATE_WIFI_AP
    global OSX_VERSION

    HOSTNAME = socket.gethostname()
    Euid = str(os.geteuid())
    Egid = str(os.getegid())

    Parser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + ' v' + __version__, version='%prog ' + __version__)
    Parser.add_option('-p', '--path', dest='RootPath', help='Path to the OS X system to audit (e.g. /mnt/xxx). The running system will be audited if not specified')
    Parser.add_option('-t', '--txtoutput', dest='TxtLogFile', help='Path to the txt output log file')
    Parser.add_option('-H', '--htmloutput', dest='HTMLLogFile', help='Path to the HTML output log file')
    Parser.add_option('-z', '--ziplogs', dest='ZipLogsFile', help='Create a zip file containing all system and users\' logs. Path to directory to put the zip file in')
    Parser.add_option('-S', '--syslog', dest='SyslogServer', default=False, help='Syslog server to send the report to')
    Parser.add_option('-a', '--all', action='store_true', default=False, help='Analyze all (it is equal to -qsidbAkUe)')
    Parser.add_option('-q', '--quarantines', action='store_true', default=False, help='Analyze quarantined files')
    Parser.add_option('-s', '--startup', action='store_true', default=False, help='Analyze startup agents and daemons ')
    Parser.add_option('-i', '--installedapps', action='store_true', default=False, help='Analyze installed applications')
    Parser.add_option('-d', '--downloads', action='store_true', default=False, help='Analyze downloaded files ')
    Parser.add_option('-b', '--browsers', action='store_true', default=False, help='Analyze browsers (Safari, FF & Chrome) ')
    Parser.add_option('-A', '--airportprefs', action='store_true', default=False, help='Analyze Airport preferences ')
    Parser.add_option('-g', '--wifiapgeolocate', action='store_true', default=False, help='Tries to geolocate WiFi AP found in AirportPrefs using Geomena.org')
    Parser.add_option('-k', '--kext', action='store_true', default=False, help='Analyze kernel extensions (kext) ')
    Parser.add_option('-U', '--usersaccounts', action='store_true', default=False, help='Analyze users\' accounts ')
    Parser.add_option('-e', '--eventlogs', action='store_true', default=False, help='Analyze system event logs')
    Parser.add_option('-m', '--mrh', action='store_true', default=False, help='Perform a reputation lookup in Team Cymru\'s MRH')
    Parser.add_option('-v', '--virustotal', action='store_true', default=False, help='Perform a lookup in VirusTotal database.')
    Parser.add_option('-l', '--localhashesdb', dest='LocalDatabase', default=False, help='Path to a local database of suspicious hashes to perform a lookup in')

    (options, args) = Parser.parse_args()

    if sys.version_info < (2, 7) or sys.version_info > (3, 0):
        PrintAndLog(u'You must use python 2.7 or greater but not python 3', 'ERROR')                        # This error won't be logged
        exit(1)

    if options.RootPath:
        ROOT_PATH = options.RootPath

    if options.TxtLogFile:
        logging.basicConfig(filename=options.TxtLogFile, filemode='w', level=logging.DEBUG)

    if options.SyslogServer:
        SyslogSetup(options.SyslogServer)

    if options.HTMLLogFile:
        try:
            HTML_LOG_FILE = codecs.open(options.HTMLLogFile, 'w', 'utf-8')
        except (IOError):
            PrintAndLog(u'Cannot open ' + options.HTMLLogFile.decode('utf-8') + u'\n', 'ERROR')
        except:
            PrintAndLog(u'HTML Log setup failed, HTML Log is disabled ', 'ERROR')
            HTML_LOG_FILE = False

    PrintAndLog('Header', 'SECTION')

    AuditedSystemVersion = GetAuditedSystemVersion()
    Timezone = GetAuditedSystemTimezone()

    PrintAndLog(u'Report generated by ' + __description__ + ' v' + __version__ + ' on ' + time.strftime('%x %X %Z') +' running as '+Euid +'/'+ Egid, 'DEBUG')
    PrintAndLog(u'Audited system path: ' + ROOT_PATH.decode('utf-8'), 'DEBUG')
    PrintAndLog(u'Version of the audited system: ' + AuditedSystemVersion, 'DEBUG')
    PrintAndLog(u'Current timezone of the audited system: ' + Timezone + '\n', 'DEBUG')


    if ROOT_PATH == '/' and (Euid != '0' and Egid != '0'):
        PrintAndLog(u'Hey! You asked me to audit the system I am running on, but I am neither euid 0 nor egid 0. I may not be able to open some files.', 'WARNING')

    if options.kext or options.all:
        ParseKext()

    if options.startup or options.all:
        ParseStartup()

    if options.installedapps or options.all:
        ParseInstalledApps()

    if options.quarantines or options.all:
        ParseQuarantines()

    if options.downloads or options.all:
        ParseDownloads()

    if options.browsers or options.all:
        ParseBrowsers()

    if options.wifiapgeolocate:
        GEOLOCATE_WIFI_AP = True

    if options.airportprefs or options.all:
        ParseAirportPrefs()

    if options.usersaccounts or options.all:
        ParseUsersAccounts()

    if options.eventlogs or options.all:
        ParseEventLogs()

    if options.ZipLogsFile:
        AggregateLogs(options.ZipLogsFile)

    if options.mrh:
        MHRLookup()

    if options.virustotal:
        if VT_API_KEY:
            VTLookup()
        else:
            PrintAndLog(u'VT_API_KEY is not set. Skipping VirusTotal lookup.', 'ERROR')

    if options.LocalDatabase:
        LocalLookup(options.LocalDatabase)

    if options.HTMLLogFile:
        HTMLLogFlush()

if __name__ == '__main__':
    Main()
