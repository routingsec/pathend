This is the agent software, which handles certification of ASes and deploys filtering rules.
It runs on Linux machines with python 2.7 (default version in Linux). The Agent application can run in two modes: 

1. a ``register'' mode, where the user can register a path-end records in the system's database. Since in this mode agent will need access to the AS's private key, run it as root. To invoke the register mode use the following command: sudo python agent.py register ASN comma_seperated_neighbors_list is_transient(True/False)
Note: the system will ensure that the user is authorized to issue a path-end record for this AS number (ASN) before storing the record in the database.

2. a ``daemon'' mode, where the agent periodically updates from the database and configures the local BGP routers with path-end filtering policies. To invoke the register mode use the following command: python agent.py daemon
The only manual configuration required (only in this mode) is to edit the manual_configuration_file.py, and include the management IP address and password for each of the network's BGP routers. After configuration, just execute as described above.

This software is already configured with the addresses on path-end repositories that we deployed in the cloud (using EC2 and GCE, at different locations and regions).
