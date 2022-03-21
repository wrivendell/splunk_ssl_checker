#!/usr/bin/env python
#
# wr_ssl_checker_query - support module for wr_ssl_checker.py
#
# Written by: Will Rivendell
# Email: wrivendell@splunk.com
# Email: contact@willrivendell.com
##############################################################################################################

# imports
from . import wr_ssl_checker_local as local
from . import wr_ssl_checker_arguments as arguments

import OpenSSL, ssl, socket, time

	# Check host is alive before getting cert
def isOpen(host: str, port: int) -> bool:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(arguments.args.timeout)
	try:
		s.connect((host, int(port)))
		s.shutdown(socket.SHUT_RDWR)
		return(True)
	except:
		return(False)
	finally:
		s.close()

def checkHost(host: str, port: int) -> bool:
	host_up = False
	for i in range(arguments.args.retry):
		if isOpen(host, port):
			host_up = True
			break
		else:
			time.sleep(arguments.args.delay)
	return(host_up)

	# cert query
def certQuery(domain: str, port: int) -> bool:
	if checkHost(domain, port):
		try:
			cert = ssl.get_server_certificate((domain, port))
			x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
			return(x509)
		except:
			return(False)
	else:
		return(False)

	# get SSL Cert info
def getCertInfo(domain: str, port: int):  #Runs from  getRawDataFromCertInfo on loop for each domain at runtime 
	success = False
	if not (arguments.args.only_use_additional_ports): #skip to additional without trying first
		x509 = certQuery(domain, port) 
		if not (x509) == False:
			success = True #if specified port is successful
			local.getRawDataFromCertInfo(x509,domain,port)
	if not (arguments.args.only_use_specified_port): #skip additional ports if True
		for p in (arguments.args.additional_ports):   #try additional listed ports if specified no work
			x509 = certQuery(domain, p)
			if not (x509) == False:
				local.getRawDataFromCertInfo(x509,domain,p)
				success = True	#loop through all log each success
			if not (success):
				local.getRawDataFromCertInfo(False,domain,port) #log only one failure if no ports responded


##############################################################################################################