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

if not os.path.exists("registrars"):
    os.makedirs("registrars")
Registrars = {"52.3.156.141": "registrars/registrar1.pem", "52.17.242.51": "registrars/registrar2.pem", "52.76.1.206": "registrars/registrar3.pem"}

StorageServer = ["52.3.156.141", "52.17.242.51", "52.76.1.206"]

PREFIX_DB_FILE = "prefix_ownership.db"

UPDATE_INTERVAL = 60 * 60 # one hour

DEBUG = True
