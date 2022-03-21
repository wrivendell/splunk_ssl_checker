#!/usr/bin/env python
#
# wr_ssl_checker_local - support module for wr_ssl_checker.py and wr_ssl_checker_query.py
#
# Written by: Will Rivendell
# Email: wrivendell@splunk.com
# Email: contact@willrivendell.com
##############################################################################################################


# imports
import csv, datetime, time, os

from . import wr_ssl_checker_arguments as arguments
from . import wr_ssl_checker_errors as errors

	## set Global var for today
today = (datetime.datetime.now().strftime("%Y-%m-%d"))

	### clear out any logs older than retention period ##
def removeOldLogFiles(directory:str):
	all_files_list = (os.listdir(directory))
	for f in all_files_list:
		if (isLogFileOld((arguments.args.outputlogpath)+(f), (arguments.args.retentiondays))):
			ilename_full = (arguments.args.outputlogpath)+(f)
			rint(filename_full)+" will be deleted"			# DEBUG
			s.remove(filename_full)

def isLogFileOld(file: str, days_old: int) -> bool:
	file_age = (time.strftime('%Y-%m-%d', time.gmtime(os.path.getmtime(file))))
	old_age = (datetime.datetime.now() - datetime.timedelta(days=(days_old))).strftime("%Y-%m-%d")
	if (file_age) < (old_age):
		return(True)
	else:
		return(False)

	# Read CSV and make list based on column number ##
def readcsv(filename: str, column: int) -> list:
	file = open(filename, "rU")
	reader = csv.reader(file, delimiter=",")
	list = []
	if (arguments.args.csvheaders) == True:
		next(file) #skip headers
	for row in reader:
		list.append(row[(column)])
	file.close()
	return(list)

	# Make dict aka map ###
def makeMap(host: str, port: int) -> dict:
	host = {z[0]:list(z[1:]) for z in zip((host),(port))}
	return(host)

	# Format validto and from dates to human readable
def formatASNDate(string: str) -> str:
	if type(string) == bytes:
		string = string.decode("utf-8") 
	string = str(string).replace("Z", "")
	date = datetime.datetime.strptime((string), "%Y%m%d%H%M%S").strftime("%Y-%m-%dT%H:%M:%S") ## time is UTC-0
	return(date)

def writeLineToFile(string: str):
	file_name = (today)+"-"+(arguments.args.outputlogname)
	text_file = open(arguments.args.outputlogpath+(file_name), "a")
	text_file.write(string)
	text_file.close()
	time.sleep(2)
	
def additionalFieldsMapping(host: str):   # additional fields maps
	if arguments.args.getdesc:
		desc = (readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.desc_col_num))
		global descMap
		descMap = makeMap((host), (desc))
	if arguments.args.getenvtype:
		envtype = (readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.envtype_col_num))
		global envtypeMap
		envtypeMap = makeMap((host), (envtype))
	if arguments.args.getaddl1:
		addl01 = (readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.addl1_col_num))
		global addl01Map
		addl01Map = makeMap((host), (addl01))
	if arguments.args.getaddl2:
		addl02 = (readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.addl2_col_num))
		global addl02Map
		addl02Map = makeMap((host), (addl02))
	if arguments.args.getaddl3:
		addl03 = (readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.addl3_col_num))
		global addl03Map
		addl03Map = makeMap((host), (addl03))
	if arguments.args.getaddl4:
		addl04 = (readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.addl4_col_num))
		global addl04Map
		addl04Map = makeMap((host), (addl04))
	if arguments.args.getaddl5:
		addl05 = (readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.addl5_col_num))
		global addl05Map
		addl05Map = makeMap((host), (addl05))
	 
def additionalFieldsLogging(domain: str) -> str:   # additional fields logline
	if arguments.args.getdesc:
		server_desc = descMap.get((domain),"")
		server_desc = str(server_desc[0])
		addl_logline = " "+"description="+(server_desc)
	if arguments.args.getenvtype:
		server_envtype = envtypeMap.get((domain),"")
		server_envtype = str(server_envtype[0])
		addl_logline = ((addl_logline)+" "+"environment_type="+(server_envtype))
	if arguments.args.getaddl1:
		addl_01 = addl01Map.get((domain),"")
		addl_01 = str(addl_01[0])
		addl_logline = ((addl_logline)+" "+(arguments.args.addl1_field_name)+"="+(addl_01))
	if arguments.args.getaddl2:
		addl_02 = addl02Map.get((domain),"")
		addl_02 = str(addl_02[0])
		addl_logline = ((addl_logline)+" "+(arguments.args.addl2_field_name)+"="+(addl_02))
	if arguments.args.getaddl3:
		addl_03 = addl03Map.get((domain),"")
		addl_03 = str(addl_03[0])
		addl_logline = ((addl_logline)+" "+(arguments.args.addl3_field_name)+"="+(addl_03))
	if arguments.args.getaddl4:
		addl_04 = addl04Map.get((domain),"")
		addl_04 = str(addl_04[0])
		addl_logline = ((addl_logline)+" "+(arguments.args.addl4_field_name)+"="+(addl_04))
	if arguments.args.getaddl5:
		addl_05 = addl05Map.get((domain),"")
		addl_05 = str(addl_05[0])
		addl_logline = ((addl_logline)+" "+(arguments.args.addl5_field_name)+"="+(addl_05))	 
		addl_logline = ((addl_logline)+'\n')
	return(addl_logline)

def getRawDataFromCertInfo(x509: bool, domain: str, port: int):   # write line to log file
	if (x509) == False:   #getCertInfo returned a fail after trying all ports
		query_status = "error"
		port_status = "error"
		x509_expired_raw = "error"
		x509_valid_from_raw = "error"
		x509_valid_to_raw = "error"
		x509_issuer_cn_raw = "error"
		x509_issuer_on_raw = "error"
		x509_subject_cn_raw = "error"
		x509_subject_on_raw = "error"
		x509_version_raw = "error"
		x509_sn_raw = "error"
		x509_hash_raw = "error"
	else:
		if (x509.has_expired()):
			x509_expired_raw = True
		else:
			x509_expired_raw = False
		port_status = (port)
		query_status = "success"
		x509_valid_from_raw =  formatASNDate(x509.get_notBefore()) #start
		x509_valid_to_raw = formatASNDate(x509.get_notAfter()) #expiry
		x509_issuer_cn_raw = x509.get_issuer().commonName #issuer common name
		x509_issuer_on_raw = x509.get_issuer().organizationName #issuer organization name
		x509_subject_cn_raw = x509.get_subject().commonName #issueeeee common name
		x509_subject_on_raw = x509.get_subject().organizationName #issueeeee organization name
		x509_version_raw = x509.get_version() #version
		x509_sn_raw = x509.get_serial_number() #serial number
		x509_hash_raw = x509.get_signature_algorithm() #algorithm
	addl_loglines = additionalFieldsLogging(domain)
	log_line = ((datetime.datetime.now()).strftime("%Y-%m-%dT%H:%M:%S")+" "+"status="+(query_status)+" "+"host="+(domain)+" "+"port="+(port_status)+" "+"sourcecsv="+(arguments.args.csvpath)+(arguments.args.csvname)+" "+"expired="+str(x509_expired_raw)+" "+"validfrom="+str(x509_valid_from_raw)+" "+"validto="+str(x509_valid_to_raw)+" "+"issuercn="+str(x509_issuer_cn_raw)+" "+"issueron="+str(x509_issuer_on_raw)+" "+"issuedtocn="+str(x509_subject_cn_raw)+" "+"issedtoon="+str(x509_subject_on_raw)+" "+"version="+str(x509_version_raw)+" "+"serial="+str(x509_sn_raw)+" "+"hashalgorithm="+str(x509_hash_raw)+(addl_loglines))
	if arguments.args.standalone:
		writeLineToFile(log_line)
	else:
		print(log_line)
 

##############################################################################################################

