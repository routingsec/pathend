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
import sys

random.seed(time.time())

def setup_keys():
    if ((not os.path.exists(Configuration.PRIVATE_KEY_FILE)) or (not os.path.exists(Configuration.PUBLIC_KEY_FILE))):
        print "generating private/public key pair, these will be stored in files named:", Configuration.PRIVATE_KEY_FILE, Configuration.PUBLIC_KEY_FILE
        GatewayKeys = M2Crypto.RSA.gen_key(2048, 65537)
        GatewayKeys.save_key(Configuration.PRIVATE_KEY_FILE, None)
        GatewayKeys.save_pub_key(Configuration.PUBLIC_KEY_FILE)

def pub_key_from_ints(e, n):
    return M2Crypto.RSA.new_pub_key((M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(hex(e)[2:])), M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(hex(n)[2:])),))
    
def sign(s):
    rsa = M2Crypto.RSA.load_key(Configuration.PRIVATE_KEY_FILE)
    digest = hashlib.new('sha256', s).digest()
    return rsa.sign(digest, "sha256")

def verify(s, signature, pub):
    try:
        bio = BIO.MemoryBuffer(pub)
        rsa = RSA.load_pub_key_bio(bio)
        pubkey = EVP.PKey()
        pubkey.assign_rsa(rsa)

        # if you need a different digest than the default 'sha1':
        pubkey.reset_context(md='sha256')
        pubkey.verify_init()
        pubkey.verify_update(s)
        return (pubkey.verify_final(signature) == 1)
    except:
        return False
    
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
def redir_to_null():
	f = open(os.devnull, 'w')
	sys.stdout = f
	sys.stderr = f
