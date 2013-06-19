# -*- encoding: utf-8 -*-

################################################################################################################
#                                                                                                              #
#                                            OS X Auditor by @Jipe_                                            #
#                                                                                                              #
#  This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.   #
#                                                                                                              #
#                                                                                                              #
################################################################################################################

import optparse
import os
import hashlib
import logging
import sqlite3
import socket
import time
import json

import biplist
import plistlib	#binary plist are not well supported

import codecs 	#plist parsing does not work in python3.3 so we are stuck in 2.7 for now

try:
	from urllib.request import urlopen	#python3
except ImportError:
	import urllib, urllib2				#python2

__description__ = 'OS X Auditor'
__author__ = '@Jipe_'
__version__ = '0.1'

ROOT_PATH = ""
HASHES = []
LOCAL_HASHES_DB = {}
HTML_LOG_FILE = False

MRH_HOST = "hash.cymru.com"
MRH_PORT = 43

MALWARE_LU_HOST = "https://www.malware.lu/api/check"
MALWARE_LU_API_KEY = ""											#Put your malware.lu API key here

VT_HOST = "https://www.virustotal.com/vtapi/v2/file/report"
VT_API_KEY  = ""												#Put your VirusTotal API key here

def HTMLLogSetup(Part):
		if Part == "HEADER":
			HTML_LOG_HEADER = """<html xmlns=\"http://www.w3.org/1999/xhtml\">
								<head>
								<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />
								<title>OS X Auditor Rapport</title>
								<style type=\"text/css\">\n"""
			try:
				with codecs.open('bootstrap.min.css', 'r', "utf-8") as f:
					Css = f.read()
			except (IOError):
				PrintAndLog("Cannot open %s \n" % bootstrap.min.css, "WARNING")
		
			HTML_LOG_HEADER += Css
			HTML_LOG_HEADER += """</style>
								</head>
								<body style=\"margin:5%\">"""	

			HTML_LOG_FILE.write(HTML_LOG_HEADER)
		
		elif Part == "FOOTER":
			HTML_LOG_FOOTER = """<body>
								</html>
								"""
			HTML_LOG_FILE.write(HTML_LOG_FOOTER)

def HTMLLog(str, MODE):
	
	if MODE == "INFO":
		HTML_LOG_FILE.write("<i class='icon-file'></i> " + str + "<br />")
	
	if MODE == "HASH":
		Splitted = str.split(" ")
		Link = "<a href=\"https://www.virustotal.com/fr/file/" + Splitted[0] + "/analysis/\">" + Splitted[0] + "</a> "
		HTML_LOG_FILE.write("<i class='icon-file'></i> " + Link + " ".join(Splitted[1:]).decode("utf-8") + "<br />")

	elif MODE == "WARNING":
		HTML_LOG_FILE.write("<i class='icon-warning-sign'></i> <span class='label label-warning'> "+ str + "</span><br />")
	
	elif MODE == "IMPORTANT":
		HTML_LOG_FILE.write("<i class='icon-fire'></i> <span class='label label-important'> " + str + "</span><br />")
	
	elif MODE == "SECTION":
		HTML_LOG_FILE.write("<h2> " + str + "</h2>")
	
	elif MODE == "SUBSECTION":
		HTML_LOG_FILE.write("<h3> " + str + "</h3>")
	
	elif MODE == "DEBUG":
		HTML_LOG_FILE.write("<i class='icon-wrench'></i> " + str + "<br />")

def PrintAndLog(str, MODE):
	if MODE == "INFO":
		print ("[INFO] " + str)
		logging.info(str)

	elif MODE == "WARNING":
		print ("[WARNING] " + str)
		logging.warning(str)

	elif MODE == "IMPORTANT":
		print ("[IMPORTANT] " + str)
		logging.warning(str)
	
	elif MODE == "SECTION":
		SectionTitle = "\n#########################################################################################################\n"
		SectionTitle += "#                                                                                                       #\n"
		SectionTitle += "#         " +str+ " "*(94-len(str)) + "#\n"
		SectionTitle += "#                                                                                                       #\n"
		SectionTitle += "#########################################################################################################\n"
		print (SectionTitle)
		logging.info("\n"+SectionTitle)
	
	elif MODE == "DEBUG":
		print ("[DEBUG] " + str)
		logging.debug(str)
	else:
		print ("[?] " + str)
		
	if HTML_LOG_FILE:
		HTMLLog (str, MODE)

def MHRLookup():
	PrintAndLog("Team Cymru MHR lookup", "SECTION")
	Query = "begin\r\n"
	for Hash in HASHES:
		Query += Hash + "\r\n"
	Query +="end\r\n"

	S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	S.connect((MRH_HOST, MRH_PORT))
	S.sendall(Query)

	Response = ''
	while True:
		Data = S.recv(4096)
		Response += Data
		if not Data: break
	S.close()
	
	Lines = Response.split("\n")
	Lines = Lines[2:-1]
	
	PrintAndLog("Got %s hashes to verify" % len(Lines), "DEBUG")
	for line in Lines:
		Status = line.split(" ")
		if Status[2] == "NO_DATA":
			PrintAndLog(line, "INFO")
		else:
			PrintAndLog(line, "IMPORTANT")

def MlwrluLookup():
	PrintAndLog("Malware.lu lookup", "SECTION")
	
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
			PrintAndLog(Hash +" "+ "N/A "+ Ret["stats"], "IMPORTANT")
		else:
			PrintAndLog(Hash +" "+ Ret["stats"] +" "+ Ret["error"], "INFO")			

def VTLookup():
	PrintAndLog("VirusTotal lookup", "SECTION")

	for Hash in HASHES:
		try:
			param = { 'resource': Hash, 'apikey': VT_API_KEY }
			data = urllib.urlencode(param)
			f = urllib2.urlopen(VT_HOST, data)
			data = f.read()	
	 	
		except (urllib2.HTTPError, e):
			if e.code == 401:
				PrintAndLog("Wrong VirusTotal key", "WARNING") 
			else:
				PrintAndLog("VirusTotal error "+str(e.code)+" "+str(e.reason), "WARNING")
	
		Ret = json.loads(data)
		
		if Ret["response_code"] == 1:
			PrintAndLog(Ret["md5"] +" "+ Ret["scan_date"] +" "+ str(Ret["positives"]) +"/"+ str(Ret["total"]), "IMPORTANT")
		else:
			PrintAndLog(Hash +" "+ "Never seen" +" "+ "0/0", "INFO")
		time.sleep(16)															# VirusTotal public API is limited to at most 4 requests of any nature in any given 1 minute time frame. Remove this line if you have a private API key. See https://www.virustotal.com/fr/documentation/public-api/

def LocalLookup(hashdbpath):
	global LOCAL_HASHES_DB
	
	PrintAndLog("Local Hashes database lookup", "SECTION")
	with open(hashdbpath, 'r') as f:
		Data = f.readlines()
		for Line in Data:
			Line = Line.split(" ")
			LOCAL_HASHES_DB[Line[0]] = Line[1]
	
	PrintAndLog(str(len(LOCAL_HASHES_DB)) + " hashes loaded from the local hashes database", "DEBUG")

	for Hash in HASHES:
		if Hash in LOCAL_HASHES_DB:
			PrintAndLog(Hash +" "+ LOCAL_HASHES_DB[Hash], "IMPORTANT")

def ParseQuarantines():
	PrintAndLog("Quarantine artifacts", "SECTION")
	
	for User in os.listdir(ROOT_PATH + "Users/"):
		if User[0] != ".":
			PrintAndLog(User +"\'s Quarantine artifacts", "SUBSECTION")
			DbPath = os.path.join(ROOT_PATH + "Users/" + User + "/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
			if os.path.isfile(DbPath):
				DbConnection = sqlite3.connect(DbPath)
				DbCursor = DbConnection.cursor()
				LSQuarantineEvents = DbCursor.execute("SELECT * from LSQuarantineEvent")
				for LSQuarantineEvent in LSQuarantineEvents:
					JointLSQuarantineEvent = ""
					for Q in LSQuarantineEvent:
						JointLSQuarantineEvent += ";" + str(Q)
					PrintAndLog(JointLSQuarantineEvent[1:]+"\n", "INFO")
				DbConnection.close()
			else:
				PrintAndLog("No quarantined files for user " + User + "\n", "WARNING")

def ParseLaunchAgents(AgentsPath, TYPE):	
	LaunchAgentPlist = False
	
	for LaunchAgent in os.listdir(AgentsPath):
		LaunchAgentPlistpath = os.path.join(AgentsPath + LaunchAgent)
		PrintAndLog(LaunchAgentPlistpath, "DEBUG")
		try:
			LaunchAgentPlist = plistlib.readPlist(LaunchAgentPlistpath)
		except (IOError):
			PrintAndLog ("Cannot open " + LaunchAgentPlistpath, "WARNING")
		except:
			try:
				LaunchAgentPlist = biplist.readPlist(LaunchAgentPlistpath)
				PrintAndLog("Trying harder to open bplist " + LaunchAgentPlistpath + "\n", "DEBUG")
			except (biplist.InvalidPlistException, biplist.NotBinaryPlistException) as e:
				PrintAndLog("Something was really wrong with " + LaunchAgentPlistpath + " (Binary or JSON plist may FAIL) \n", "WARNING")
		
		if LaunchAgentPlist:
			if "ProgramArguments" in LaunchAgentPlist and "Label" in LaunchAgentPlist:
				FilePath = LaunchAgentPlist["ProgramArguments"][0]
				try:
					with open(FilePath, 'rb')	as f:	
						data = f.read()
						Md5 = hashlib.md5(data).hexdigest()
						HASHES.append(Md5)
						PrintAndLog(Md5 +" "+ FilePath + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "HASH")
						if len(LaunchAgentPlist["ProgramArguments"]) >= 3:
							if (LaunchAgentPlist["ProgramArguments"][2].find("exec") != -1) or (LaunchAgentPlist["ProgramArguments"][2].find("socket") != -1):
								PrintAndLog(LaunchAgentPlist["ProgramArguments"][2]+" in " + LaunchAgentPlistpath + " looks suspicious", "WARNING")
						
				except (IOError):
					PrintAndLog("Cannot open %s \n" % LaunchAgentPlist["ProgramArguments"][0], "WARNING")
			elif "Program" in LaunchAgentPlist and "Label" in LaunchAgentPlist:
				FilePath = LaunchAgentPlist["Program"]
				try:
					with open(FilePath, 'rb') as f:
						data = f.read()
						Md5 = hashlib.md5(data).hexdigest()
						HASHES.append(Md5)
						PrintAndLog(Md5 +" "+ FilePath + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "HASH")
				except (IOError):
					PrintAndLog("Cannot open %s \n" % LaunchAgentPlist["Program"], "WARNING")

def ParseStartup():
	PrintAndLog("Startup artifacts", "SECTION")

	PrintAndLog("System Agents artifacts", "SUBSECTION")
	ParseLaunchAgents(ROOT_PATH + "System/Library/LaunchAgents/", "SystemLaunchAgents")
	
	PrintAndLog("System Daemons artifacts", "SUBSECTION")
	ParseLaunchAgents(ROOT_PATH + "System/Library/LaunchDaemons/", "SystemLaunchDaemons")
	
	PrintAndLog("Third party Agents artifacts", "SUBSECTION")
	ParseLaunchAgents(ROOT_PATH + "Library/LaunchAgents/", "ThirdPartyLaunchAgents")
	
	PrintAndLog("Third party Daemons artifacts", "SUBSECTION")
	ParseLaunchAgents(ROOT_PATH + "Library/LaunchDaemons/", "ThirdPartyLaunchDaemons")
	
	PrintAndLog("Users\' Agents artifacts", "SECTION")
	for User in os.listdir("/Users/"):
		if User[0] != "." and os.path.isdir("/users/" + User + "/Library/LaunchAgents/"):
			PrintAndLog(User +"\'s Agents artifacts", "SUBSECTION")
			ParseLaunchAgents("/Users/" + User + "/Library/LaunchAgents/", User + " user LaunchDaemons")

def ParseDownloads():
	PrintAndLog("Users\' Downloads artifacts", "SECTION")
	for User in os.listdir(ROOT_PATH + "Users/"):
		DlUserPath = ROOT_PATH + "Users/" + User + "/Downloads/"
		if User[0] != "." and os.path.isdir(DlUserPath):
			PrintAndLog(User +"\'s Downloads artifacts", "SUBSECTION")
			for Root, Dirs, Files in os.walk(DlUserPath):
				for File in Files:
					FilePath = os.path.join(Root, File)
					with open(FilePath, "rb") as f:
						data = f.read()
						Md5 = hashlib.md5(data).hexdigest()
						HASHES.append(Md5)
						PrintAndLog(Md5 +" "+ FilePath + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "HASH")
	
def DumpSQLiteDb(SQLiteDbPath):

	PrintAndLog(SQLiteDbPath, "SECTION")

	if os.path.isfile(SQLiteDbPath):
		DbConnection = sqlite3.connect(SQLiteDbPath)
		DbCursor = DbConnection.cursor()
		DbCursor.execute("SELECT * from sqlite_master WHERE type = 'table'")
		Tables =  DbCursor.fetchall()
		for Table in Tables:
			PrintAndLog(Table[2], "SUBSECTION")
			DbCursor.execute("SELECT * from " + Table[2])
			Rows = DbCursor.fetchall()
			for Row in Rows:
				PrintAndLog(str(Row), "INFO")	
			
		DbConnection.close()
	else:
		PrintAndLog(DbPath + "not found\n", "WARNING")

def ParseFirefoxProfile(User, Profile):
	PrintAndLog(User +"\'s Firefox profile artifacts (" +Profile+ ")", "SECTION")

	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "cookies.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "downloads.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "formhistory.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "permissions.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "places.sqlite"))
	DumpSQLiteDb(os.path.join(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile, "signons.sqlite"))
	
	#TODO key3.db

def ParseFirefox():
	PrintAndLog("Users\' Firefox artifacts", "SECTION")
	for User in os.listdir(ROOT_PATH + "Users/"):
		if User[0] != "." and os.path.isdir(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles"):
			PrintAndLog(User +"\'s Firefox artifacts", "SUBSECTION")
			for Profile in os.listdir(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles"):
				if Profile[0] != "." and os.path.isdir(ROOT_PATH + "Users/" + User + "/Library/Application Support/Firefox/Profiles/" + Profile):
					ParseFirefoxProfile(User, Profile)

def ParseSafariProfile(User, Path):
	HistoryPlist = False
	DownloadsPlist = False
	
	PrintAndLog(User + "\'s Safari Downloads Artifacts", "SUBSECTION")
	DownloadsPlistPath = os.path.join(Path + "/Downloads.plist")
	PrintAndLog(DownloadsPlistPath, "DEBUG")
	
	try:
		DownloadsPlist = plistlib.readPlist(DownloadsPlistPath)
	except (IOError):
		PrintAndLog ("Cannot open " + DownloadsPlistPath, "WARNING")
	except:
			try:
				PrintAndLog("Trying harder to open bplist " + DownloadsPlistPath + "\n", "DEBUG")
				DownloadsPlist = biplist.readPlist(DownloadsPlistPath)
			except (biplist.InvalidPlistException, biplist.NotBinaryPlistException) as e:
				PrintAndLog("Something was really wrong with " + DownloadsPlistPath + " (Binary or JSON plist may FAIL) \n", "WARNING")
	
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

	try:
		HistoryPlist = plistlib.readPlist(HistoryPlistPath)
	except (IOError):
		PrintAndLog ("Cannot open " + HistoryPlistPath, "WARNING")
	except :
		try:
			PrintAndLog("Trying harder to open bplist " + HistoryPlistPath + "\n", "DEBUG")
			HistoryPlist = biplist.readPlist(HistoryPlistPath)
		except (biplist.InvalidPlistException, biplist.NotBinaryPlistException) as e:
			PrintAndLog("Something was really wrong with " + HistoryPlistPath + " (Binary or JSON plist may FAIL) \n", "WARNING")
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

	try:
		TopSitesPlist = plistlib.readPlist(TopSitesPlistPath)
	except (IOError):
		PrintAndLog ("Cannot open " + TopSitesPlistPath, "WARNING")
	except :
		try:
			PrintAndLog("Trying harder to open bplist " + TopSitesPlistPath + "\n", "DEBUG")
			TopSitesPlist = biplist.readPlist(TopSitesPlistPath)
		except (biplist.InvalidPlistException, biplist.NotBinaryPlistException) as e:
			PrintAndLog("Something was really wrong with " + TopSitesPlistPath + " (Binary or JSON plist may FAIL) \n", "WARNING")
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
	PrintAndLog("Users\' Chrome artifacts", "SECTION")
	# TODO
	
def ParseBrowsers():
	PrintAndLog("Browsers artifacts", "SECTION")

	PrintAndLog("Safari artifacts", "SECTION")
	ParseSafari()

	PrintAndLog("Firefox artifacts", "SECTION")
	ParseFirefox()
	
	PrintAndLog("Chrome artifacts", "SECTION")
	ParseChrome()

def ParseKext():
	PrintAndLog("Kernel extensions artifacts", "SECTION")

	Kextpath = ROOT_PATH + "System/Library/Extensions/"
	plistfile = "/Info.plist"
	InfoPlistpath = ""
	CFBundleExecutablepath = ""
	
	for Kextension in os.listdir(Kextpath):
		for kext in os.listdir(Kextpath + Kextension):
			if os.path.isfile(os.path.join(Kextpath + Kextension + plistfile)):
				InfoPlistpath = os.path.join(Kextpath + Kextension + plistfile)
				CFBundleExecutablepath = "/"
			else:
				InfoPlistpath = os.path.join(Kextpath + Kextension + "/Contents" + plistfile)
				CFBundleExecutablepath = "/Contents/MacOS/"
		try:
			PrintAndLog (InfoPlistpath, "DEBUG")
			InfoPlist = plistlib.readPlist(InfoPlistpath)
		except (IOError):
			PrintAndLog ("Cannot open " + InfoPlistpath, "WARNING")
		except:
			try:
				PrintAndLog("Trying harder to open bplist " + InfoPlistpath, "DEBUG")
				InfoPlist = biplist.readPlist(InfoPlistpath)
			except (biplist.InvalidPlistException, biplist.NotBinaryPlistException) as e:
				PrintAndLog("Something was really wrong with " + InfoPlistpath + " (Binary or JSON plist may FAIL) \n", "WARNING")
		
		if InfoPlist:
			if "CFBundleExecutable" in InfoPlist:
				FilePath = os.path.join(Kextpath + Kextension + CFBundleExecutablepath + InfoPlist["CFBundleExecutable"])
				try:
					with open(FilePath, 'rb') as f:
						data = f.read()
						Md5 = hashlib.md5(data).hexdigest()
						PrintAndLog(Md5 +" "+ Kextension + " - " + time.ctime(os.path.getctime(FilePath)) + " - " + time.ctime(os.path.getmtime(FilePath))+"\n", "HASH")
				except:
					PrintAndLog("Something was wrong with " + FilePath, "WARNING")
			else:
				PrintAndLog("Something was wrong with " + Kextension + ". Couldn\'t fint the CFBundleExecutable key in Info.plist\n", "WARNING")
	
def Main():
	
	Euid = str(os.geteuid())
	Egid = str(os.getegid())
	
	global ROOT_PATH
	global HTML_LOG_FILE
	
	Parser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + " v" + __version__, version='%prog ' + __version__)
	Parser.add_option('-p', '--path', dest="RootPath", help='Path to the OS X system to audit (e.g. /mnt/xxx). The running system will be audited if not specified')
	Parser.add_option('-l', '--log', dest="LogFile", help='Path to the output raw log file')
	Parser.add_option('-H', '--html', dest="HTMLLogFile", help='Path to the output HTML log file')
	Parser.add_option('-a', '--all', action="store_true", default=False, help='Analyse all artifacts')
	Parser.add_option('-q', '--quarantine', action="store_true", default=False, help='Analyse quarantined artifacts')
	Parser.add_option('-s', '--startup', action="store_true", default=False, help='Analyse startup agents and daemons artifacts')
	Parser.add_option('-d', '--downloads', action="store_true", default=False, help='Analyse downloaded files artifacts')
	Parser.add_option('-b', '--browsers', action="store_true", default=False, help='Analyse browsers (Safari, FF & Chrome) artifacts')
	Parser.add_option('-k', '--kext', action="store_true", default=False, help='Analyse kernel extensions (kext) artifacts')
	Parser.add_option('-m', '--mrh', action="store_true", default=False, help='Perform a reputation lookup in Team Cymru\'s MRH')
	Parser.add_option('-u', '--malwarelu', action="store_true", default=False, help='Perform a reputation lookup in Malware.lu database')
	Parser.add_option('-v', '--vt', action="store_true", default=False, help='Perform a lookup in VirusTotal database.')
	Parser.add_option('-L', '--local', dest="LocalDatabase", default=False, help='Path to a local hash database to perform a lookup in')

	(options, args) = Parser.parse_args()

	if options.RootPath:
		ROOT_PATH = RootPath
	else:
		ROOT_PATH = "/"
		
	if options.LogFile:
		logging.basicConfig(filename=options.LogFile, filemode='w', level=logging.DEBUG)

	if options.HTMLLogFile:
		if HTML_LOG_FILE is False:
			try:
				HTML_LOG_FILE = codecs.open(options.HTMLLogFile, 'w', "utf-8")
			except (IOError):
				PrintAndLog("Cannot open %s \n" % options.HTMLLogFile, "WARNING")
		
		HTMLLogSetup("HEADER")

	PrintAndLog(__description__ +" Rapport", "SECTION")
	PrintAndLog("Rapport generated by "+ __description__ + " v" + __version__ + " on " + time.strftime('%x %X %Z') +" running as "+Euid +"/"+ Egid +"\n", "DEBUG")

	if ROOT_PATH == "/" and (Euid != "0" and Egid != "0"):
		PrintAndLog("Hey! You asked me to audit the system I am running on, but I am neither euid 0 nor egid 0. I may not be able to open some files.", "WARNING")
	
	if options.kext or options.all:
		ParseKext()

	if options.startup or options.all:
		ParseStartup()

	if options.quarantine or options.all:	
		ParseQuarantines()

	if options.downloads or options.all:
		ParseDownloads()
		
	if options.browsers or options.all:
		ParseBrowsers()
		
	if options.mrh:
		MHRLookup()

	if options.malwarelu:
		if MALWARE_LU_API_KEY:
			MlwrluLookup()
		else:
			PrintAndLog("MALWARE_LU_API_KEY is not set. Skipping Malware.lu lookup.", "WARNING")

	if options.vt:
		if VT_API_KEY:
			VTLookup()
		else:
			PrintAndLog("VT_API_KEY is not set. Skipping VirusTotal lookup.", "WARNING")
	
	if options.LocalDatabase:
		LocalLookup(options.LocalDatabase)
	
	if options.HTMLLogFile:
		if HTML_LOG_FILE:
			HTMLLogSetup("FOOTER")
			HTML_LOG_FILE.close()
		
if __name__ == '__main__':
	Main()
