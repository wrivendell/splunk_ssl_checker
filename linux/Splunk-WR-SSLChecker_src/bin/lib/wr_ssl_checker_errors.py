#!/usr/bin/env python
#
# wr_ssl_checker_errors - support module for wr_ssl_checker.py, wr_ssl_checker_query.py, wr_ssl_checker_local.py, wr_ssl_checker_arguments.py
#
# Written by: Will Rivendell
# Email: wrivendell@splunk.com
# Email: contact@willrivendell.com
##############################################################################################################


# imports
import os, sys
from . import wr_ssl_checker_arguments as arguments

	# Print Error and Exit
def errorPrint(error: str):
	print("ERROR")
	print("ERROR: "+(error))
	print("ERROR")
	sys.exit()

	# check logpath writable
def checkLogPathPermission():
	if not os.path.exists(arguments.args.outputlogpath):
		checkLogPathPermission((arguments.args.outputlogpath)+" has an issue. Or we can't write logs here. Please verify.")

	# file not found # called from wr_ssl_checker_local.py
def csvFileNotFound():
	checkLogPathPermission((arguments.args.csvname)+" file NOT found, please check the ssl_checker.properties for proper name and path.")


#########

def sanityCheck(): ### runs from start of wr_ssl_checker.py
	#check output dir
	if arguments.args.standalone:
		if not os.path.exists(arguments.args.outputlogpath):
			errorPrint((arguments.args.outputlogpath)+" has an issue. Or we can't write logs here. Please verify.")
	#check csv is valid
	try:
		file = open((arguments.args.csvpath)+(arguments.args.csvname), "rU")
		file.close()
	except:
		errorPrint((arguments.args.csvname)+" file NOT found, please check the ssl_checker.properties for proper name and path.")
	## retry cannot be zero
		if arguments.args.retry <= 0:
			arguments.args.retry = 1
	## must have some port to check
	if arguments.args.only_use_specified_port and arguments.args.only_use_additional_ports:
		errorPrint("--only_use_specified_port and --only_use_additional_ports cannot both be TRUE, please set accordingly")
