import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import installmissing
import SocketServer
import httplib, urllib
import protocol_messages
import pickle
import netaddr
import LocalThreads
import Configuration
import M2Crypto
import os
import time
import socket
import threading
import utils
import requestcatcher
import zlib
import configure
import deploy_rules
import signal
import sys

ServerThread = LocalThreads.ThreadPool(1)
RegistrarPool = LocalThreads.ThreadPool(len(Configuration.Registrars))

My_Public_Key = None
RegistrarSignatures = {}

# clean exit on CRTL+C
def signal_handler(signal, frame):
	deploy_rules.exit()
	sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def get_public_key():
	"""
	Retrieves the public key of this agent from the repository.
	"""
	global My_Public_Key

	# Create the private/public keys if they are missing
	utils.setup_keys()	
	f = file(Configuration.PUBLIC_KEY_FILE, "r")
	My_Public_Key = f.read()
	f.close()
	
class SvPDDRequestHandler(SocketServer.BaseRequestHandler):
        """
        The RequestHandler class for our server.
        It is instantiated once per connection to the server, and must
        override the handle() method to implement communication to the
        client.
        """
        def handle(self):
                """
                Generate response for a challenge and send it back.
                """
                # self.request is the TCP socket connected to the client
                data = self.request.recv(1024)
                self.data = data.strip()
        	
        	# parse out the challenge
                challenge_message = pickle.loads(zlib.decompress(self.data))
                if (challenge_message.as_number not in Configuration.ASes.keys()):
                        return
                if (challenge_message.network not in Configuration.ASes[challenge_message.as_number][0]):
                        return
        
                # generate the response
                resp = protocol_messages.response(My_Public_Key, challenge_message.as_number, challenge_message.network, challenge_message.challenge, challenge_message.real_dest)
                
                # compress it and send
                self.request.sendall(pickle.dumps(resp))

def fetch_signature(registrar, params, headers, lock):
	# get a registrar's signature-share for the certificate
	global RegistrarSignatures
	print "connecting to registrar", registrar
	try:
		conn = httplib.HTTPConnection(registrar)
	
		# post the request to initiate the prefix-ownership procedure.
		conn.request("POST", "", params, headers)
	
		# wait for the response...
		response = conn.getresponse()
		
		# prefix-ownership authentication procedure completed
		if (response.status == 200):
			print "Received valid certificate share from registrar", registrar
			sig = pickle.loads(zlib.decompress(response.read())).sig
			lock.acquire()
			RegistrarSignatures[registrar] = sig
			lock.release()
		else:
			print "ERROR:", response.status
	except:
		print "could not connect..."

def send_to_storage(RPKI_cert):
	"""
	Store the signed certificate in the repository.
	"""
	for prefixDB in Configuration.StorageServer:
		try:
			print "storing certificate @ Prefix-DB server:", prefixDB
			params = pickle.dumps(RPKI_cert)
			headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
			conn = httplib.HTTPConnection(prefixDB, 8080)
			conn.request("POST", "", params, headers)
			response = conn.getresponse()
			if (response.status != 200):
				print "Failed to store the RPKI certificate"
		except:
			pass

def request_to_certify(as_number, network, neighbours):
	"""
	Send the request to initiate the certification procedure to all registrars.
	"""
	global RegistrarSignatures
	
	# create the request
	cert_request = protocol_messages.certification_request(My_Public_Key, as_number, network)
	params = pickle.dumps(cert_request)
	headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
	lock = threading.RLock()
	for registrar in Configuration.Registrars.keys():
		RegistrarPool.add_task(fetch_signature, registrar, params, headers, lock)
	RegistrarPool.wait_completion()

	print "++++ Prefix " + str(network) + " Ownership Certification Process Complete for AS number " + str(as_number) + " ++++"
	# Check that the signature shares are valid
	RPKI_cert = protocol_messages.signed_RPKI_cert(cert_request, RegistrarSignatures, neighbours, utils.sign_links(neighbours))
	for registrar in RPKI_cert.signatures.keys():
		# if signature share is invalid then remove it
		if (not utils.verify(RPKI_cert.certification, RPKI_cert.signatures[registrar], registrar)):
			del RPKI_cert.signatures[registrar]
	# if we have enough signature shares, send the signed certificate to the prefix-DBs
	if (len(RPKI_cert.signatures.keys()) >= Configuration.MIN_SIGNERS):
		print "sending Prefix Ownership Certificate to prefix-DBs"
		send_to_storage(RPKI_cert)

def answer_requests(server):
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
	server.serve_forever()

def main():
	configure.main()
	deploy_rules.main()
if __name__ == "__main__":
    main()

