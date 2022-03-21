#!/usr/bin/env python
#
# wr_ssl_checker_arguments - support module for wr_ssl_checker.py, wr_ssl_checker_local.py, wr_ssl_checker_query.py
#
# Written by: Will Rivendell
# Email: wrivendell@splunk.com
# Email: contact@willrivendell.com
##############################################################################################################


# imports
import argparse

### class for loading arguments (command line switches) file.properties ###
class LoadFromFile (argparse.Action):
	def __call__ (self, parser, namespace, values, option_string = None):
		with values as f:
			parser.parse_args(f.read().split(), namespace)

### define common "string values" for bool args
def str2bool(v: str) -> bool:
	if isinstance(v, bool):
		return(v)
	if v.lower() in ('yes', 'true', 't', 'y', '1'):
		return(True)
	elif v.lower() in ('no', 'false', 'f', 'n', '0'):
		return(False)
	else:
		raise argparse.ArgumentTypeError('Boolean value expected.')

### arguments the app will accept - load from file:  wr_ssl_checker.properties
def arguments():
	global parser
	parser = argparse.ArgumentParser()
	parser.add_argument('--file', type=open, action=LoadFromFile)
	parser.add_argument('--csvpath', default='.', help="The full path to csv, eg: /home/user/files/ ", type=lambda x: str(x.replace('\s', ' ').replace('\"\"', '')))
	parser.add_argument('--csvname', default='test.csv', help="The csv name eg: globalServerList.csv  ", type=lambda x: str(x.replace('\s', ' ').replace('\"\"', '')))
	parser.add_argument('--csvheaders', type=str2bool, nargs='?', const=True, default=True, help="Does the CSV have headers? (True or False)")
	parser.add_argument('--host_col_num', default='0', help="Column number host is in ( 0 is first column )", type=int)
	parser.add_argument('--port_col_num', default='1', help="Column number port is in ( 0 is first column )", type=int)
	parser.add_argument('--only_use_specified_port', type=str2bool, nargs='?', const=True, default=False, help="Only use port listed in col of CSV don't try additional. (True or False)")
	parser.add_argument('--additional_ports', nargs='*', help="Additional ports to try if SSL listening port fails or is unknown", required=False)
	parser.add_argument('--only_use_additional_ports', type=str2bool, nargs='?', const=True, default=True, help="Only use additional ports (ignores port col in csv) (True or False)")
	parser.add_argument('--getdesc', type=str2bool, nargs='?', const=True, default=True, help="Do you want the desc field from your CSV as a Splunk field? (True or False)")
	parser.add_argument('--desc_col_num', default='1', help="Column number desc is in ( 0 is first column )", type=int)
	parser.add_argument('--getenvtype', type=str2bool, nargs='?', const=True, default=True, help="Do you want the env type field from your CSV as a Splunk field? (True or False)")
	parser.add_argument('--envtype_col_num', default='4', help="Column number envtype is in ( 0 is first column )", type=int)	
	parser.add_argument('--timeout', default='1', help="When to timeout and stop trying host (sec) ", type=int)
	parser.add_argument('--retry', default='1', help="How many times to retry )", type=int)
	parser.add_argument('--delay', default='1', help="Time between retries (sec) ", type=int)
	parser.add_argument('--standalone', type=str2bool, nargs='?', const=True, default=False, help="Run as Standalone and log files in log folder for monitoring? Or False to let Splunk run script and log output (True or False)")
	parser.add_argument('--outputlogpath', default='./', help="The full path to where you're writing the logfile, eg: /var/log/ssl_monitor ", type=lambda x: str(x.replace('\s', ' ').replace('\"\"', '')))
	parser.add_argument('--outputlogname', default='ssl_checker', help="The name you want the new log to be called. NOTE: Current day auto appended to the front and include a txt or log extension if wanted ", type=lambda x: str(x.replace('\s', ' ').replace('\"\"', '')))
	parser.add_argument('--enablelogroll', type=str2bool, nargs='?', const=True, default=True, help="Automatically remove old log files? True or False")
	parser.add_argument('--retentiondays', default='10', help="How many days old does a file need to be, before its purged", type=int)
### Additional Fields
	parser.add_argument('--getaddl1', type=str2bool, nargs='?', const=True, default=False, help="Do you want to use this additional field from your CSV as a Splunk field? (True or False)")
	parser.add_argument('--addl1_col_num', default='7', help="Column number additional field is in ( 0 is first column )", type=int)	
	parser.add_argument('--addl1_field_name', default='addl_01', help="Additional field name you'd like to use. (no special chars or spaces, use udnerscores...i.e. my_field_name", type=str)		
	parser.add_argument('--getaddl2', type=str2bool, nargs='?', const=True, default=False, help="Do you want to use this additional field from your CSV as a Splunk field? (True or False)")
	parser.add_argument('--addl2_col_num', default='7', help="Column number additional field is in ( 0 is first column )", type=int)	
	parser.add_argument('--addl2_field_name', default='addl_02', help="Additional field name you'd like to use. (no special chars or spaces, use udnerscores...i.e. my_field_name", type=str)
	parser.add_argument('--getaddl3', type=str2bool, nargs='?', const=True, default=False, help="Do you want to use this additional field from your CSV as a Splunk field? (True or False)")
	parser.add_argument('--addl3_col_num', default='7', help="Column number additional field is in ( 0 is first column )", type=int)	
	parser.add_argument('--addl3_field_name', default='addl_03', help="Additional field name you'd like to use. (no special chars or spaces, use udnerscores...i.e. my_field_name", type=str)
	parser.add_argument('--getaddl4', type=str2bool, nargs='?', const=True, default=False, help="Do you want to use this additional field from your CSV as a Splunk field? (True or False)")
	parser.add_argument('--addl4_col_num', default='7', help="Column number additional field is in ( 0 is first column )", type=int)	
	parser.add_argument('--addl4_field_name', default='addl_04', help="Additional field name you'd like to use. (no special chars or spaces, use udnerscores...i.e. my_field_name", type=str)
	parser.add_argument('--getaddl5', type=str2bool, nargs='?', const=True, default=False, help="Do you want to use this additional field from your CSV as a Splunk field? (True or False)")
	parser.add_argument('--addl5_col_num', default='7', help="Column number additional field is in ( 0 is first column )", type=int)	
	parser.add_argument('--addl5_field_name', default='addl_05', help="Additional field name you'd like to use. (no special chars or spaces, use udnerscores...i.e. my_field_name", type=str)

#######################################################################
arguments()
args = parser.parse_args()

##############################################################################################################
