"""
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
"""

import os 

def install():
	"""
	Installs all missing packages.
	"""
	try:
		from M2Crypto import X509
	except:
		print "Installing missing package M2Crypto for cryptographic functions" 
		if (os.geteuid() != 0):
			print "error - must run as root to install package" 
			raise "you must run as root to install the package, please use \"sudo python PnP-IPsec\" to execute"
		os.system("apt-get --assume-yes install python-m2crypto")

	try:
		import netifaces
	except:
		print "Installing missing package netifaces for reading network routing information (python-netifaces)" 
		if (os.geteuid() != 0):
			print "error - must run as root to install package" 
			raise "you must run as root to install the package, please use \"sudo python PnP-IPsec\" to execute"
		os.system("apt-get --assume-yes install python-netifaces")

	try:
		import netaddr
	except:
		print "Installing missing package netifaces for reading network routing information (python-netaddr)" 
		if (os.geteuid() != 0):
			print "error - must run as root to install package" 
			raise "you must run as root to install the package, please use \"sudo python PnP-IPsec\" to execute"
		os.system("apt-get --assume-yes install python-netaddr")
				
	return True

		
install()