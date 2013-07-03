# -*- encoding: utf-8 -*-
#
#  OS X Auditor
#  
#  Author: Jean-Philippe Teissier ( @Jipe_ ) 
#    
#  This work is licensed under the GNU General Public License
#

__description__ = 'OS X Auditor'
__author__ = '@Jipe_'
__version__ = '0.2.1'

ROOT_PATH = "/"
HASHES = []
LOCAL_HASHES_DB = {}
HTML_LOG_FILE = False

FOUNDATION_IS_IMPORTED = False
BIPLIST_IS_IMPORTED  = False
PLISTLIB_IS_IMPORTED = False

SYSLOG_SERVER = False												
SYSLOG_PORT = 514												#You can change your SYSLOG port here 
HOSTNAME = ""

MRH_HOST = "hash.cymru.com"
MRH_PORT = 43

MALWARE_LU_HOST = "https://www.malware.lu/api/check"
MALWARE_LU_API_KEY = ""											#Put your malware.lu API key here

VT_HOST = "https://www.virustotal.com/vtapi/v2/file/report"
VT_API_KEY  = ""												#Put your VirusTotal API key here

import optparse
import os
import sys
import hashlib
import logging
from logging.handlers import SysLogHandler
import sqlite3
import socket
import time
import json
import zipfile
import codecs 													#binary plist parsing does not work well in python3.3 so we are stuck in 2.7 for now
from functools import partial

try:
	from urllib.request import urlopen							#python3
except ImportError:
	import urllib, urllib2										#python2

try:
	import Foundation											#It only works on OS X
	FOUNDATION_IS_IMPORTED = True
	print("DEBUG: Mac OS X Obj-C Foundation successfully imported")
except ImportError:
	print("DEBUG: Cannot import Mac OS X Obj-C Foundation. Installing PyObjC on OS X is highly recommended")
	try: 
		import biplist
		BIPLIST_IS_IMPORTED = True
	except ImportError:
		print("DEBUG: Cannot import the biplist lib. I may not be able to properly parse a binary pblist")
	try:
		import plistlib
		PLISTLIB_IS_IMPORTED = True
	except ImportError:
		print("DEBUG: Cannot import the plistlib lib. I may not be able to properly parse a binary pblist")
	
def HTMLLogSetup(Part):
	""" Create the header and the footer of the HTML report """
	
	if Part == "HEADER":
		HTML_LOG_HEADER = """<html xmlns=\"http://www.w3.org/1999/xhtml\">
							<head>
							<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />
							<title>OS X Auditor Rapport</title>
							<link rel=\"stylesheet\" type=\"text/css\" href=\"bootstrap/css/bootstrap.min.css\">
							</head>
							<body style=\"margin:5%\">"""	

		HTML_LOG_FILE.write(HTML_LOG_HEADER)
	
	elif Part == "FOOTER":
		HTML_LOG_FOOTER = """<body>
							</html>
							"""
		HTML_LOG_FILE.write(HTML_LOG_FOOTER)

def HTMLLog(LogStr, TYPE):
	""" Write a string of HTML log depending of its type """
	
	if TYPE == "INFO":
		Splitted = LogStr.split(" ")
		if len(Splitted[0]) == 32:	
			Link = "<a href=\"https://www.virustotal.com/fr/file/" + Splitted[0] + "/analysis/\">" + Splitted[0] + "</a> "
			HTML_LOG_FILE.write("<i class='icon-file'></i> " + Link + " ".join(Splitted[1:]).decode("utf-8") + "<br />")
		else:
			HTML_LOG_FILE.write("<i class='icon-file'></i> " + LogStr + "<br />")

	elif TYPE == "WARNING":
		HTML_LOG_FILE.write("<i class='icon-fire'></i> <span class='label label-important'> "+ LogStr + "</span><br />")
	
	elif TYPE == "ERROR":
		HTML_LOG_FILE.write("<i class='icon-warning-sign'></i> <span class='label label-warning'> "+ LogStr + "</span><br />")
	
	elif TYPE == "SECTION":
		HTML_LOG_FILE.write("<h2> " + LogStr + "</h2>")
	
	elif TYPE == "SUBSECTION":
		HTML_LOG_FILE.write("<h3> " + LogStr + "</h3>")
	
	elif TYPE == "DEBUG":
		HTML_LOG_FILE.write("<i class='icon-wrench'></i> " + LogStr + "<br />")
	
def SyslogSetup(SyslogServer):
	""" Set the Syslog handler up"""

	global SYSLOG_SERVER
	
	Logger = logging.getLogger()
	Syslog = logging.handlers.SysLogHandler(address=(SyslogServer, SYSLOG_PORT))
	Formatter = logging.Formatter("OS X Auditor: "+HOSTNAME+" %(levelname)s: %(message)s")
	Syslog.setFormatter(Formatter)
	Logger.addHandler(Syslog)
	SYSLOG_SERVER = True

def PrintAndLog(LogStr, TYPE):
	""" Write a string of log depending of its type and call the function to generate the HTML log or the Syslog if needed """
	
	global HTML_LOG_FILE
	global SYSLOG_SERVER
	
	if TYPE == "INFO":
		print ("[INFO] " + LogStr)
		logging.info(LogStr)
		
	elif TYPE == "ERROR":
		print ("[ERROR] " + LogStr)
		logging.error(LogStr)

	elif TYPE == "WARNING":
		print ("[WARNING] " + LogStr)
		logging.warning(LogStr)
	
	elif TYPE == "DEBUG":
		print ("[DEBUG] " + LogStr)
		logging.debug(LogStr)
	
	elif TYPE == "SECTION" or TYPE == "SUBSECTION":
		SectionTitle = "\n#########################################################################################################\n"
		SectionTitle += "#                                                                                                       #\n"
		SectionTitle += "#         " +LogStr+ " "*(94-len(LogStr)) + "#\n"
		SectionTitle += "#                                                                                                       #\n"
		SectionTitle += "#########################################################################################################\n"
		print (SectionTitle)
		logging.info("\n"+SectionTitle)
	
	if HTML_LOG_FILE:
		HTMLLog(LogStr, TYPE)

def MHRLookup():
	""" Perform of lookup in Team Cymru\'s MHR """
	
	PrintAndLog("Team Cymru MHR lookup", "SECTION")
	PrintAndLog("Got %s hashes to verify" % len(HASHES), "DEBUG")

	Query = "begin\r\n"
	for Hash in HASHES:
		Query += Hash + "\r\n"
	Query +="end\r\n"

	S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	S.connect((MRH_HOST, MRH_PORT))
	S.sendall(Query)

	Response = ""
	while True:
		Data = S.recv(4096)
		Response += Data
		if not Data: break
	S.close()
	
	Lines = Response.split("\n")
	Lines = Lines[2:-1]
	
	for line in Lines:
		Status = line.split(" ")
		if Status[2] == "NO_DATA":
			PrintAndLog(line, "INFO")
		else:
			PrintAndLog(line, "WARNING")

def MlwrluLookup():
	""" Perform of lookup in Malware.lu database """

	PrintAndLog("Malware.lu lookup", "SECTION")
	PrintAndLog("Got %s hashes to verify" % len(HASHES), "DEBUG")

	for Hash in HASHES:
		try:
			param = { 'hash': Hash, 'apikey': MALWARE_LU_API_KEY }
			data = urllib.urlencode(param)
			f = urllib2.urlopen(MALWARE_LU_HOST, data)
			data = f.read()	
	 	
		except (urllib2.HTTPError, e):
			if e.code == 401:
				PrintAndLog("Wrong Malware.lu api key", "WARNING") 
			else:
				PrintAndLog("Malware.lu error "+str(e.code)+" "+str(e.reason), "WARNING")
	
		Ret = json.loads(data)
		
		if Ret["status"]:
			PrintAndLog(Hash +" "+ "N/A "+ Ret["stats"], "WARNING")
		else:
			PrintAndLog(Hash +" "+ Ret["stats"] +" "+ Ret["error"], "INFO")			

def VTLookup():
	""" Perform of lookup in VirusTotal database """

	PrintAndLog("VirusTotal lookup", "SECTION")
	PrintAndLog("Got %s hashes to verify" % len(HASHES), "DEBUG")

	try:
		param = { 'resource': ','.join(HASHES), 'apikey': VT_API_KEY }
		data = urllib.urlencode(param)
		f = urllib2.urlopen(VT_HOST, data)
		data = f.read()	
 	
	except (urllib2.HTTPError, e):
		if e.code == 401:
			PrintAndLog("Wrong VirusTotal key", "ERROR") 
		else:
			PrintAndLog("VirusTotal error "+str(e.code)+" "+str(e.reason), "ERROR")

	Ret = json.loads(data)
	
	Results = []
	if type(Ret) is dict:
		Results.append(Ret)
	elif type(Ret) is list:
		Results = Ret

	for Entry in Results:
		if Entry["response_code"] == 1:
			if Entry["positives"] > 0:
				PrintAndLog(Entry["md5"] +" "+ Entry["scan_date"] +" "+ str(Entry["positives"]) +"/"+ str(Entry["total"]), "WARNING")
			else:
				PrintAndLog(Entry["md5"] +" "+ Entry["scan_date"] +" "+ str(Entry["positives"]) +"/"+ str(Entry["total"]), "INFO")
		elif Entry["response_code"] == 0:
			PrintAndLog(Entry["resource"] +" "+ "Never seen" +" "+ "0/0", "INFO")
		else:
			PrintAndLog("Got a weird answer from Virustotal\n", "ERROR")

def LocalLookup(HashDBPath):
	""" Perform of lookup in a local database """

	global LOCAL_HASHES_DB
	
	PrintAndLog("Local Hashes database lookup", "SECTION")
	PrintAndLog("Got %s hashes to verify" % len(HASHES), "DEBUG")

	with open(HashDBPath, 'r') as f:
		Data = f.readlines()
		for Line in Data:
			if Line[0] != "#":
				Line = Line.split(" ")
				LOCAL_HASHES_DB[Line[0]] = Line[1]
				
	PrintAndLog(str(len(LOCAL_HASHES_DB)) + " hashes loaded from the local hashes database", "DEBUG")

	for Hash in HASHES:
		if Hash in LOCAL_HASHES_DB:
			PrintAndLog(Hash +" "+ LOCAL_HASHES_DB[Hash], "WARNING")

def BigFileMd5(FilePath):
	""" Return the md5 hash of a big file """
	
	Md5 = hashlib.md5()
	try:
		with open(FilePath, 'rb') as f:
			for Chunk in iter(partial(f.read, 1048576), ''):
				Md5.update(Chunk)
	except:
		PrintAndLog("Cannot hash %s \n" % FilePath, "ERROR")
		return False
	return Md5.hexdigest()

def UniversalReadPlist(PlistPath):
	""" Try to read a plist depending of the plateform and the available libs. Good luck Jim... """
	
	plistDictionnary = False
	
	if FOUNDATION_IS_IMPORTED:
		plistNSData, errorMessage = Foundation.NSData.dataWithContentsOfFile_options_error_(PlistPath, Foundation.NSUncachedRead, None)
		if errorMessage is not None or plistNSData is None:
			PrintAndLog("Unable to read in the data from the plist file: %s - %s" % (PlistPath, errorMessage), "ERROR")
		plistDictionnary, plistFormat, errorMessage = Foundation.NSPropertyListSerialization.propertyListFromData_mutabilityOption_format_errorDescription_(plistNSData, Foundation.NSPropertyListMutableContainers, None, None)
		if errorMessage is not None or plistDictionnary is None:
			PrintAndLog("Unable to read in the data from the plist file: %s - %s" % (PlistPath, errorMessage), "ERROR")
		if not hasattr(plistDictionnary, "has_key"):
			PrintAndLog("The plist does not have a dictionary as its root as expected: %s" % PlistPath, "ERROR")	
		return plistDictionnary
	else:
		if BIPLIST_IS_IMPORTED:
			try:
				plistDictionnary = biplist.readPlist(PlistPath)
			except (IOError):
				PrintAndLog ("Cannot open " + PlistPath, "ERROR")
			except:
				PrintAndLog("Cannot parse " + PlistPath + " (Binary or JSON plist may FAIL) \n", "ERROR")
			return plistDictionnary
		
		elif PLISTLIB_IS_IMPORTED:
			try:
				plistDictionnary = plistlib.readPlist(PlistPath)
			except (IOError):
				PrintAndLog ("Cannot open " + PlistPath, "ERROR")
			except:
				PrintAndLog("Cannot parse " + PlistPath + " (Binary or JSON plist may FAIL) \n", "ERROR")
			return plistDictionnary	
		else:
			PrintAndLog("Cannot parse " + PlistPath + ". No plist lib available.\n", "ERROR")
			return False
	
def ParseQuarantines():
	""" Parse users\' quarantines """

	PrintAndLog("Quarantine artifacts", "SECTION")
	
	for User in os.listdir(os.path.join(ROOT_PATH + "Users/")):
		if User[0] != ".":
			PrintAndLog(User +"\'s Quarantine artifacts", "SUBSECTION")
			DbPathV2 = os.path.join(ROOT_PATH + "Users/" + User + "/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")		# OS X >= 10.7
			DbPathV1 = os.path.join(ROOT_PATH + "Users/" + User + "/Library/Preferences/com.apple.LaunchServices.QuarantineEvents")			# OS X <= 10.6
			if os.path.isfile(DbPathV2):
				DbPath = DbPathV2
			elif os.path.isfile(DbPathV1):
				DbPath = DbPathV1
			else:
				PrintAndLog("No quarantined files for user " + User + "\n", "INFO")
				continue
			DbConnection = sqlite3.connect(DbPath)
			DbCursor = DbConnection.cursor()
			LSQuarantineEvents = DbCursor.execute("SELECT * from LSQuarantineEvent")
			for LSQuarantineEvent in LSQuarantineEvents:
				JointLSQuarantineEvent = u""
				for Q in LSQuarantineEvent:
					JointLSQuarantineEvent += u";" + unicode(Q)
				PrintAndLog(JointLSQuarantineEvent[1:]+"\n", "INFO")
			DbConnection.close()

def ParseStartupItems (StartupItemsPath):
	""" Parse the StartupItems plist and hash its program argument """

	StartupItemsPlist = False
	
	for StartupItems in os.listdir(StartupItemsPath):
		StartupItemsPlistPath = os.path.join(StartupItemsPath + StartupItems + "/StartupParameters.plist")
		
		PrintAndLog(StartupItemsPlistPath, "DEBUG")
		StartupItemsPlist = UniversalReadPlist(StartupItemsPlistPath)
		
		if StartupItemsPlist:
			if "Provides" in StartupItemsPlist:
				FilePath = os.path.join(StartupItemsPath + StartupItems + "/" + StartupItemsPlist["Provides"][0])
				Md5 = BigFileMd5(FilePath)
				if Md5:
					HASHES.append(Md5)
					PrintAndLog(Md5 +" "+ FilePath + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "INFO")

def ParseLaunchAgents(AgentsPath):
	""" Parse a LanchAgent plist and hash its program argument. Also look for suspicious keywords in the plist itself """
	
	SuspiciousPlist = ["exec", "socket" ,"open", "connect"]
	LaunchAgentPlist = False
	
	for LaunchAgent in os.listdir(AgentsPath):
		LaunchAgentPlistpath = os.path.join(AgentsPath + LaunchAgent)
		
		PrintAndLog(LaunchAgentPlistpath, "DEBUG")
		LaunchAgentPlist = UniversalReadPlist(LaunchAgentPlistpath)
		
		if LaunchAgentPlist:
			if "Program" in LaunchAgentPlist and "Label" in LaunchAgentPlist:
				FilePath = LaunchAgentPlist["Program"]
				Md5 = BigFileMd5(FilePath)
				if Md5:
					HASHES.append(Md5)
					PrintAndLog(Md5 +" "+ FilePath + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "INFO")
				continue
			if "ProgramArguments" in LaunchAgentPlist and "Label" in LaunchAgentPlist:
				FilePath = LaunchAgentPlist["ProgramArguments"][0]
				Md5 = BigFileMd5(FilePath)
				if Md5:
					HASHES.append(Md5)
					PrintAndLog(Md5 +" "+ FilePath + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "INFO")
				if len(LaunchAgentPlist["ProgramArguments"]) >= 3:
					if any(x in LaunchAgentPlist["ProgramArguments"][2] for x in SuspiciousPlist):
						PrintAndLog(LaunchAgentPlist["ProgramArguments"][2]+" in " + LaunchAgentPlistpath + " looks suspicious", "WARNING")
			
def ParseStartup():
	""" Parse the different LauchAgents and LaunchDaemons artifacts """

	PrintAndLog("Startup artifacts", "SECTION")

	PrintAndLog("System Agents artifacts", "SUBSECTION")
	ParseLaunchAgents(os.path.join(ROOT_PATH + "System/Library/LaunchAgents/"))
	
	PrintAndLog("System Daemons artifacts", "SUBSECTION")
	ParseLaunchAgents(os.path.join(ROOT_PATH + "System/Library/LaunchDaemons/"))
	
	PrintAndLog("Third party Agents artifacts", "SUBSECTION")
	ParseLaunchAgents(os.path.join(ROOT_PATH + "Library/LaunchAgents/"))
	
	PrintAndLog("Third party Daemons artifacts", "SUBSECTION")
	ParseLaunchAgents(os.path.join(ROOT_PATH + "Library/LaunchDaemons/"))

	PrintAndLog("System Scripting Additions artifacts", "SUBSECTION")
	ParsePackagesDir(os.path.join(ROOT_PATH + "System/Library/ScriptingAdditions/"))

	PrintAndLog("Third party Scripting Additions artifacts", "SUBSECTION")
	ParsePackagesDir(os.path.join(ROOT_PATH + "Library/ScriptingAdditions/"))

	# Parse the old and deprecated Startup Items
	PrintAndLog("Deprecated system StartupItems artifacts", "SUBSECTION")
	ParseStartupItems(os.path.join(ROOT_PATH + "System/Library/StartupItems/"))
	
	PrintAndLog("Deprecated third party StartupItems artifacts", "SUBSECTION")
	ParseStartupItems(os.path.join(ROOT_PATH + "Library/StartupItems/"))
	
	PrintAndLog("Users\' Agents artifacts", "SUBSECTION")
	for User in os.listdir("/Users/"):
		if User[0] != "." and os.path.isdir("/users/" + User + "/Library/LaunchAgents/"):
			PrintAndLog(User +"\'s Agents artifacts", "SUBSECTION")
			ParseLaunchAgents(os.path.join("/Users/" + User + "/Library/LaunchAgents/"))

def ParseDownloads():
	""" Hash all users\' downloaded files """

	PrintAndLog("Users\' Downloads artifacts", "SECTION")
	for User in os.listdir(ROOT_PATH + "Users/"):
		DlUserPath = ROOT_PATH + "Users/" + User + "/Downloads/"
		if User[0] != "." and os.path.isdir(DlUserPath):
			PrintAndLog(User +"\'s Downloads artifacts", "SUBSECTION")
			for Root, Dirs, Files in os.walk(DlUserPath):
				for File in Files:
					FilePath = os.path.join(Root, File)
					Md5 = BigFileMd5(FilePath)
					if Md5:
						HASHES.append(Md5)
						PrintAndLog(Md5 +" "+ FilePath + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "INFO")
	
def DumpSQLiteDb(SQLiteDbPath):
	""" Dump a SQLite database file """

	PrintAndLog(SQLiteDbPath, "SECTION")
	if os.path.isfile(SQLiteDbPath):
		DbConnection = sqlite3.connect(SQLiteDbPath)
		DbCursor = DbConnection.cursor()
		DbCursor.execute("SELECT * from sqlite_master WHERE type = 'table'")
		Tables =  DbCursor.fetchall()
		for Table in Tables:
			PrintAndLog("Table " +Table[2], "SUBSECTION")
			DbCursor.execute("SELECT * from " + Table[2])
			Rows = DbCursor.fetchall()
			for Row in Rows:
				PrintAndLog(str(Row), "INFO")
		DbConnection.close()
	else:
		PrintAndLog(SQLiteDbPath + "not found\n", "ERROR")

def ParseFirefoxProfile(User, Profile):
	""" Parse the different SQLite databases in a Firefox profile """

	PrintAndLog(User +"\'s Firefox profile artifacts (" +Profile+ ")", "SECTION")
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "cookies.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "downloads.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "formhistory.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "permissions.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "places.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "signons.sqlite"))

def ParseFirefox():
	""" Walk in all users' FireFox profiles and call ParseFirefoxProfile() """
	
	PrintAndLog("Users\' Firefox artifacts", "SECTION")
	for User in os.listdir(ROOT_PATH + "Users/"):
		if User[0] != "." and os.path.isdir(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles"):
			PrintAndLog(User +"\'s Firefox artifacts", "SUBSECTION")
			for Profile in os.listdir(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles"):
				if Profile[0] != "." and os.path.isdir(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile):
					ParseFirefoxProfile(User, Profile)

def ParseSafariProfile(User, Path):
	""" Parse the different plist and SQLite databases in a Safari profile """

	HistoryPlist = False
	DownloadsPlist = False
	
	PrintAndLog(User + "\'s Safari Downloads Artifacts", "SUBSECTION")
	DownloadsPlistPath = os.path.join(Path + "/Downloads.plist")
	PrintAndLog(DownloadsPlistPath, "DEBUG")
	
	DownloadsPlist = UniversalReadPlist(DownloadsPlistPath)
	
	if DownloadsPlist:
		if "DownloadHistory" in DownloadsPlist:
			Downloads = DownloadsPlist["DownloadHistory"]
			for DL in Downloads:
				str = u""
				str += DL["DownloadEntryURL"] + " -> " + DL["DownloadEntryPath"] + " (" + DL["DownloadEntryIdentifier"] +")\n"
				PrintAndLog(str, "INFO")

	PrintAndLog(User + "\'s Safari History Artifacts", "SUBSECTION")
	HistoryPlistPath = os.path.join(Path+ "/History.plist")
	PrintAndLog(HistoryPlistPath, "DEBUG")

	HistoryPlist = UniversalReadPlist(HistoryPlistPath)

	if HistoryPlist:
		if "WebHistoryDates" in HistoryPlist:
			History =  HistoryPlist["WebHistoryDates"]
			for H in History:
				str = ""
				if "title" in H:
					str += H["title"] + " - "
				if "diplayTitle" in H:
					str += H["diplayTitle"] + " - "
				str += H[""] + "\n"
				PrintAndLog(str, "INFO")
	
	PrintAndLog(User + "\'s Safari TopSites Artifacts", "SUBSECTION")
	TopSitesPlistPath = os.path.join(Path+ "/TopSites.plist")
	
	PrintAndLog(TopSitesPlistPath, "DEBUG")
	TopSitesPlist = UniversalReadPlist(TopSitesPlistPath)

	if TopSitesPlist:
		if "TopSites" in TopSitesPlist:
			TopSites =  TopSitesPlist["TopSites"]
			for T in TopSites:
				if "TopSiteTitle" in T:
					str += T["TopSiteTitle"] + " - "
				str += T["TopSiteURLString"] + "\n"	
				PrintAndLog(str , "INFO")
	
	PrintAndLog(User + "\'s Safari Databases Artifacts", "SECTION")
	for Db in os.listdir(os.path.join(Path + "/Databases/")):
		DumpSQLiteDb(os.path.join(Path + "/Databases/" + Db))
	
	PrintAndLog(User + "\'s Safari LocalStorage Artifacts", "SECTION")
	for Db in os.listdir(os.path.join(Path + "/LocalStorage/")):
		DumpSQLiteDb(os.path.join(Path + "/LocalStorage/" + Db))

def ParseSafari():
	PrintAndLog("Users\' Safari artifacts", "SECTION")
	for User in os.listdir(os.path.join(ROOT_PATH + "Users/")):
		if User[0] != "." and os.path.isdir(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Safari")):
			PrintAndLog(User +"\'s Safari artifacts", "SECTION")
			ParseSafariProfile(User, os.path.join(ROOT_PATH + "Users/" + User + "/Library/Safari"))

def ParseChrome():
	""" Parse the different files in a Chrome profile """

	PrintAndLog("Users\' Chrome artifacts", "SECTION")
	PrintAndLog("Not implemented yet", "DEBUG")
	# TODO
	
def ParseBrowsers():
	""" Call the different functions to parse the browsers artifacts  """

	PrintAndLog("Browsers artifacts", "SECTION")

	PrintAndLog("Safari artifacts", "SECTION")
	ParseSafari()

	PrintAndLog("Firefox artifacts", "SECTION")
	ParseFirefox()
	
	#PrintAndLog("Chrome artifacts", "SECTION")
	#ParseChrome()

def ParsePackagesDir(PackagesDirPath):
	""" Parse the packages in a directory"""

	plistfile = "/Info.plist"
	PackagePlistPath = ""
	CFBundleExecutablepath = ""
	
	for PackagePath in os.listdir(PackagesDirPath):
		if os.path.isfile(os.path.join(PackagesDirPath + PackagePath + plistfile)):
			PackagePlistPath = os.path.join(PackagesDirPath + PackagePath + plistfile)
			CFBundleExecutablepath = "/"
		else:
			PackagePlistPath = os.path.join(PackagesDirPath + PackagePath + "/Contents" + plistfile)
			CFBundleExecutablepath = "/Contents/MacOS/"

		PrintAndLog (os.path.join(PackagesDirPath + PackagePath), "DEBUG")
		PackagePlist = UniversalReadPlist(PackagePlistPath)
	
		if PackagePlist:
			if "CFBundleExecutable" in PackagePlist:
				FilePath = os.path.join(PackagesDirPath + PackagePath + CFBundleExecutablepath + PackagePlist["CFBundleExecutable"])
				Md5 = BigFileMd5(FilePath)
				if Md5:
					HASHES.append(Md5)
					PrintAndLog(Md5 +" "+ FilePath + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "INFO")
			else:
				PrintAndLog("Cannot find the CFBundleExecutable key in " + PackagePlistPath + "\'s Info.plist\n", "ERROR")

def ParseKext():
	""" Parse the Kernel extensions """
	
	PrintAndLog("Kernel extensions artifacts", "SECTION")
	ParsePackagesDir(os.path.join(ROOT_PATH + "System/Library/Extensions/"))

def AggregateLogsDir(ZipHandle, LogDirPath):
	""" Aggregate all logs found in a directory to a zipball """

	for Root, Dirs, Files in os.walk(LogDirPath):
		for File in Files:
			FilePath = os.path.join(Root, File)
			try:
				ZipHandle.write(FilePath)
				PrintAndLog("Log file " + FilePath + " added to the logs zipball", "INFO")
			except:
				PrintAndLog(FilePath + " aggregation FAILED", "ERROR")

def AggregateLogs(ZipLogsFile):
	""" Walk in the different log directories to add all logs to a zipball """

	PrintAndLog("Log files aggregation", "SECTION")
	ZipLogsFilePath = os.path.join(ZipLogsFile + "/OSXAuditor_report_" + HOSTNAME + "_" + time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + ".zip")
	PrintAndLog("All log files are aggregated in " + ZipLogsFilePath, "DEBUG")
	try:
		with zipfile.ZipFile(ZipLogsFilePath, 'w') as ZipLogsFile:
			PrintAndLog(os.path.join(ROOT_PATH + "var/log") + " Log files aggregation", "SUBSECTION")
			AggregateLogsDir(ZipLogsFile, os.path.join(ROOT_PATH + "var/log"))
			PrintAndLog(os.path.join(ROOT_PATH + "Library/logs") + " Log files aggregation", "SUBSECTION")
			AggregateLogsDir(ZipLogsFile, os.path.join(ROOT_PATH + "Library/logs"))
			for User in os.listdir(os.path.join(ROOT_PATH + "Users/")):
				if User[0] != ".":
					PrintAndLog(os.path.join(ROOT_PATH + "Users/" + User + "/Library/logs") + " Log files aggregation", "SUBSECTION")
					AggregateLogsDir(ZipLogsFile, os.path.join(ROOT_PATH + "Users/" + User + "/Library/logs"))
	except Exception as e:
		PrintAndLog("Log files aggregation FAILED " + str(e.args), "ERROR")

def Main():
	""" Here we go """

	global ROOT_PATH
	global HTML_LOG_FILE
	global HOSTNAME

	HOSTNAME = socket.gethostname()
	Euid = str(os.geteuid())
	Egid = str(os.getegid())

	Parser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + " v" + __version__, version='%prog ' + __version__)
	Parser.add_option('-p', '--path', dest="RootPath", help='Path to the OS X system to audit (e.g. /mnt/xxx). The running system will be audited if not specified')
	Parser.add_option('-t', '--txtoutput', dest="TxtLogFile", help='Path to the txt output log file')
	Parser.add_option('-H', '--htmloutput', dest="HTMLLogFile", help='Path to the HTML output log file')
	Parser.add_option('-z', '--ziplogs', dest="ZipLogsFile", help='Create a zip file containing all system and users\' logs. Path to directory to put the zip file in')
	Parser.add_option('-S', '--syslog', dest="SyslogServer", default=False, help='Syslog server to send the report to')
	Parser.add_option('-a', '--all', action="store_true", default=False, help='Analyse all artifacts (equal to -qsdbk)')
	Parser.add_option('-q', '--quarantines', action="store_true", default=False, help='Analyse quarantined artifacts')
	Parser.add_option('-s', '--startup', action="store_true", default=False, help='Analyse startup agents and daemons artifacts')
	Parser.add_option('-d', '--downloads', action="store_true", default=False, help='Analyse downloaded files artifacts')
	Parser.add_option('-b', '--browsers', action="store_true", default=False, help='Analyse browsers (Safari, FF & Chrome) artifacts')
	Parser.add_option('-k', '--kext', action="store_true", default=False, help='Analyse kernel extensions (kext) artifacts')
	Parser.add_option('-m', '--mrh', action="store_true", default=False, help='Perform a reputation lookup in Team Cymru\'s MRH')
	Parser.add_option('-u', '--malwarelu', action="store_true", default=False, help='Perform a reputation lookup in Malware.lu database')
	Parser.add_option('-v', '--virustotal', action="store_true", default=False, help='Perform a lookup in VirusTotal database.')
	Parser.add_option('-l', '--localhashesdb', dest="LocalDatabase", default=False, help='Path to a local database of suspicious hashes to perform a lookup in')

	(options, args) = Parser.parse_args()

	if sys.version_info < (2, 7) or sys.version_info > (3, 0):
		PrintAndLog("You must use python 2.7 or greater but not python 3", "ERROR")						# This error won't be logged
		exit(1)
		
	if options.RootPath:
		ROOT_PATH = options.RootPath

	if options.TxtLogFile:
		logging.basicConfig(filename=options.TxtLogFile, filemode='w', level=logging.DEBUG)

	if options.SyslogServer:
		SyslogSetup(options.SyslogServer)
	
	if options.HTMLLogFile:
		try:
			HTML_LOG_FILE = codecs.open(options.HTMLLogFile, 'w', "utf-8")
		except (IOError):
			PrintAndLog("Cannot open %s \n" % options.HTMLLogFile, "ERROR")
		
		HTMLLogSetup("HEADER")

	PrintAndLog(__description__ +" Report", "SECTION")
	PrintAndLog("Report generated by "+ __description__ + " v" + __version__ + " on " + time.strftime('%x %X %Z') +" running as "+Euid +"/"+ Egid +" on "+ ROOT_PATH + "\n", "DEBUG")

	if ROOT_PATH == "/" and (Euid != "0" and Egid != "0"):
		PrintAndLog("Hey! You asked me to audit the system I am running on, but I am neither euid 0 nor egid 0. I may not be able to open some files.", "WARNING")

	if options.kext or options.all:
		ParseKext()

	if options.startup or options.all:
		ParseStartup()

	if options.quarantines or options.all:	
		ParseQuarantines()

	if options.downloads or options.all:
		ParseDownloads()
		
	if options.browsers or options.all:
		ParseBrowsers()
		
	if options.ZipLogsFile:
		AggregateLogs(options.ZipLogsFile)

	if options.mrh:
		MHRLookup()

	if options.malwarelu:
		if MALWARE_LU_API_KEY:
			MlwrluLookup()
		else:
			PrintAndLog("MALWARE_LU_API_KEY is not set. Skipping Malware.lu lookup.", "ERROR")

	if options.virustotal:
		if VT_API_KEY:
			VTLookup()
		else:
			PrintAndLog("VT_API_KEY is not set. Skipping VirusTotal lookup.", "ERROR")
	
	if options.LocalDatabase:
		LocalLookup(options.LocalDatabase)
	
	if options.HTMLLogFile:
		if HTML_LOG_FILE:
			HTMLLogSetup("FOOTER")
			HTML_LOG_FILE.close()
	
if __name__ == '__main__':
	Main()
