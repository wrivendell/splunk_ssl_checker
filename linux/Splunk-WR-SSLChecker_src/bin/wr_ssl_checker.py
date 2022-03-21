#!/usr/bin/env python
#
# wr_ssl_checker
#
# This app is used to generate log files from SSL certs. See README.txt and README.pdf for help
# TLDR: Probes open SSL ports on hosts in a csv and return certificate info in a nice log format -
#
# Written by: Will Rivendell
# Email: wrivendell@splunk.com
# Email: contact@willrivendell.com
#
###
###
###  usage: python ssl_checkere.py --file ssl_chcker.properties
###  usage: add your settings to ssl_checker.properties
###
###  Note: validto/from times are in UTC-0 (zulu time)
###  Note: this relies on wr_ssl_checker_local.py and wr_ssl_checker_query.py located in subfolder lib
###
##############################################################################################################

# imports
from lib import wr_ssl_checker_arguments as arguments
from lib import wr_ssl_checker_local as local
from lib import wr_ssl_checker_query as query
from lib import wr_ssl_checker_errors as errors

#######################################################################
## sanity check - log folder is good
#local.checkLogPathPermission()
errors.sanityCheck()

## 0 ## remove log files older than retention period
if (arguments.args.enablelogroll):
	local.removeOldLogFiles(arguments.args.outputlogpath)

## 1 ## get list of hosts from CSV
host = (local.readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.host_col_num))

## 2 ## get list of ports for hosts from CSV
port = (local.readcsv((arguments.args.csvpath)+(arguments.args.csvname), arguments.args.port_col_num))

## 3 ## create a map of hosts and their ports to loop through
main_map = local.makeMap((host), (port))

## 4 ## create a map of additional fields to loop through if specified
local.additionalFieldsMapping(host)

## 5 ##  Loop through map and check each certificate from host
for x in main_map:
	for y in main_map[x]:
	 query.getCertInfo(x,y)

## main loop = check paths -> clear old logs -> read hosts into list -> read ports into list -> merge lists to map -> loop list and get data from cert -> write each line to file