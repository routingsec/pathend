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
from auto_configuration_file import *
from manual_configuration_file import *

# destination port for DISCO challenges
DiscoPort = 8888

# the paths to the key files

if not os.path.exists("keys"):
    os.makedirs("keys")
PRIVATE_KEY_FILE = 'keys/private.pem'
PUBLIC_KEY_FILE = 'keys/public.pem'

MIN_SIGNERS = 2

StorageServer = ["52.23.243.4", "52.19.108.4", "54.254.136.249"]

PREFIX_DB_FILE = "prefix_ownership.db"

UPDATE_INTERVAL = 60 * 60 # one hour

# Specify the IP addresses of your AS's BGP routers and map them to the administrative password. Seperate each bgp router address and password pair by comma.
# Example: bgp_routers ={1.1.1.1 : secret_password, 1.1.1.2 : secret_password}
bgp_routers = {}

DEBUG = True
