This is the DISCO-agent software, which handles certification of ASes and deploys filtering rules.
It runs on Linux machines with python 2.7 (default version in Linux). Since this program will need access to the AS's private key, run it as root.
The only manual configuration required is to edit the manual_configuration_file.py, and include the management IP address and password for each of the network's BGP routers.
This software is already configured with the addresses on registrars and prefix-DBs we deployed in the cloud (at different locations and regions).