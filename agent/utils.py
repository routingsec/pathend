import netaddr
import random
import time
import M2Crypto
import hashlib
import os
import Configuration
from M2Crypto import BIO, RSA, EVP
import pickle
import telnetlib

random.seed(time.time())

def PickAddress(network):
	print "Pick Address", network
	x = 32 - network.prefixlen
	if (x == 0):
		dest = netaddr.IPAddress(network.network.value)
		if (not dest.is_unicast()):
			raise Exception("Invalid Single Address Exception")
		return dest

	attempt = 0 
	while (True):
		c = random.randrange(0, 2**x - 1)	
		addr = network.network.value + c
		dest = netaddr.IPAddress(addr)
		if (dest.is_unicast):
			return dest
		attempt += 1
		if (attempt == 10):
			raise ("No valid address")

def PickChallenge():
	return random.randrange(0, 2**64 - 1)

def setup_keys():	
	if ((not os.path.exists(Configuration.PRIVATE_KEY_FILE)) or (not os.path.exists(Configuration.PUBLIC_KEY_FILE))):
		print "generating private/public key pair, these will be stored in files named:", Configuration.PRIVATE_KEY_FILE, Configuration.PUBLIC_KEY_FILE 	
		GatewayKeys = M2Crypto.RSA.gen_key(1024, 65537)
		GatewayKeys.save_key(Configuration.PRIVATE_KEY_FILE, None)
		GatewayKeys.save_pub_key(Configuration.PUBLIC_KEY_FILE)

def sign(cert_request):
	raw_sig_input = pickle.dumps(cert_request)
	rsa = M2Crypto.RSA.load_key(Configuration.PRIVATE_KEY_FILE)
	digest = hashlib.new('sha256', raw_sig_input).digest()	
	return rsa.sign(digest, "sha256")

def sign_links(links):
	raw_sig_input = pickle.dumps(links)
	rsa = M2Crypto.RSA.load_key(Configuration.PRIVATE_KEY_FILE)
	digest = hashlib.new('sha256', raw_sig_input).digest()	
	return rsa.sign(digest, "sha256")


def verify(cert_request, signature, registrar):
	try:
		pub_key_file = file(Configuration.Registrars[registrar],"r")
		pem = pub_key_file.read()
		pub_key_file.close()
		bio = BIO.MemoryBuffer(pem)
		rsa = RSA.load_pub_key_bio(bio)
		pubkey = EVP.PKey()
		pubkey.assign_rsa(rsa)

		# if you need a different digest than the default 'sha1':
		pubkey.reset_context(md='sha256')
		pubkey.verify_init()
		pubkey.verify_update(pickle.dumps(cert_request))
		return (pubkey.verify_final(signature) == 1)
	except:
		print "failed to verify signature from " + registrar
		return False

def verify_links(RPKI_cert):
	links = RPKI_cert.links
	signature = RPKI_cert.signature_for_links
	pub = RPKI_cert.certification.public_key
	try:
		bio = BIO.MemoryBuffer(pub)
		rsa = RSA.load_pub_key_bio(bio)
		pubkey = EVP.PKey()
		pubkey.assign_rsa(rsa)

		# if you need a different digest than the default 'sha1':
		pubkey.reset_context(md='sha256')
		pubkey.verify_init()
		pubkey.verify_update(pickle.dumps(links))
		return (pubkey.verify_final(signature) == 1)
	except:
		print "failed to verify signature from " + registrar
		return False

def verify_path_end_record(record):
	if (len(record.signatures.keys()) < Configuration.MIN_SIGNERS):
		return False

	for registrar in record.signatures.keys():
		if (not verify(record.certification, record.signatures[registrar], registrar)):
			del record.signatures[registrar]

	if (len(record.signatures.keys()) < Configuration.MIN_SIGNERS):
		return False

	if (not verify_links(record)):
		return False

	return True

def create_connection(bgp_router):
	if (Configuration.DEBUG):
		return None
	tn = telnetlib.Telnet(bgp_router)
	tn.read_until("Password: ")
	tn.write(Configuration.bgp_routers[bgp_router] + "\n")
	return tn

def close_connection(connection):
	if (Configuration.DEBUG):
		return
	connection.close()
