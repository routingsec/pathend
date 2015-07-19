"""
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
"""


# transaction timeout (seconds)
TIMEOUT = 30

# the paths to the key files
PRIVATE_KEY_FILE = 'keys/private.pem'
PUBLIC_KEY_FILE = 'keys/public.pem'

MIN_SIGNERS = 1

Registrars = {"54.152.171.26": "registrars/registrar1.pem", "52.16.27.195": "registrars/registrar2.pem", "52.74.13.72": "registrars/registrar3.pem"}

PREFIX_DB_FILE = "prefix_ownership.db"
