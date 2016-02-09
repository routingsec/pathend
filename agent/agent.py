import logging
import sys
import os
import os.path
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import installmissing
import httplib, urllib
import protocol_messages
import pickle
import Configuration
import time
import socket
import utils
import configure
import deploy_rules
import signal

My_Public_Key = None
RegistrarSignatures = {}

# clean exit on CRTL+C
def signal_handler(signal, frame):
    deploy_rules.exit()
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def send_to_storage(signed_path_end_record):
    """
    Store the signed certificate in the repository.
    """
    fail_count = 0
    for prefixDB in Configuration.StorageServer:
        try:
            print "storing path-end record @ Prefix-DB server:", prefixDB
            params = pickle.dumps(signed_path_end_record)
            headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
            conn = httplib.HTTPConnection(prefixDB, 8080)
            conn.request("POST", "", params, headers)
            response = conn.getresponse()
            if (response.status != 200):
                fail_count += 1
        except:
            raise
    if fail_count == len(Configuration.StorageServer):
        print "Failed to store the path-end record (are you the RPKI-verified owner of asn", signed_path_end_record.get().asn, "?)"

def register(as_number, neighbours, transient_flag):
    """
    Send the request to initiate the certification procedure to all registrars.
    """
    path_end_record = protocol_messages.SignedPathEndRecord(as_number, neighbours, transient_flag)
    send_to_storage(path_end_record)

def main():
    if len(sys.argv) < 2:
        print "usage:", sys.argv[0], "register/deamon"
        return

    if not os.path.exists("keys"):
            os.makedirs("keys")

    utils.setup_keys()

    if sys.argv[1] == "register":
        if len(sys.argv) != 5:
            print "usage:", sys.argv[0], "register asn comma_seperated_neighbors_list is_transient(True/False)"
        as_number = int(sys.argv[2])
        neighbours = sys.argv[3].split(",")
        transient_flag = True
        if sys.argv[3] == "False":
            transient_flag = False
        register(as_number, neighbours, transient_flag)
    elif sys.argv[1] == "daemon":
        configure.main()
        deploy_rules.main()
    else:
        print "unrecognized option", sys.argv[1]
if __name__ == "__main__":
    main()
