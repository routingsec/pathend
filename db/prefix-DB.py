import installmissing
import time
import BaseHTTPServer
import pickle
import Configuration
import protocol_messages
from LocalThreads import *
import utils
import M2Crypto
import hashlib
import zlib
import RPKI
import os
import os.path

HOST_NAME = '0.0.0.0'
PORT_NUMBER = 8080

prefix_DB = {}

###################################
## Database management functions ##
###################################
def load_db():
	try:
		global prefix_DB
		dbfile = file(Configuration.PREFIX_DB_FILE, "r")
		prefix_DB = pickle.load(dbfile)
	except:
		pass
def store_db():
	global prefix_DB
	dbfile = file(Configuration.PREFIX_DB_FILE, "w")
	pickle.dump(prefix_DB, dbfile)

def store(path_end_record):
        if (record.asn in prefix_DB) and (record.timestamp <= prefix_DB[record.asn].timestamp):
                return
	prefix_DB[record.asn] = record
	store_db()

gRPKITree = RPKI.RPKITree()
class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
	"""
	Handles the database requests.
	"""
	def do_HEAD(s):
		s.send_response(200)
		s.send_header("Content-type", "text/html")
		s.end_headers()
	def do_GET(s):
		"""Respond to a GET request."""
		print "looking for", s.path
		lookup_net = s.path.replace("/","")
		try:
			if (lookup_net != "all"):
				cert = prefix_DB[lookup_net]
				s.send_response(200)
				s.end_headers()
				s.wfile.write(zlib.compress(pickle.dumps(cert)))
			else:
				s.send_response(200)
				s.end_headers()
				s.wfile.write(zlib.compress(pickle.dumps(prefix_DB)))
		except:
			s.send_response(500)
			s.end_headers()			
	def do_POST(s):
		"""Respond to a POST request."""
		try:
                        print "handling post!"
			length = int(s.headers.getheader('content-length'))
			data = s.rfile.read(length)
			signed_path_end_record = pickle.loads(data)
			record = signed_path_end_record.get()
			authorized_pubkeys = gRPKITree.get_pub_key_set(record.asn)
			print "validating"
			for pubkey in authorized_pubkeys:
                                if (utils.verify(signed_path_end_record.record, signed_path_end_record.signature, pubkey)):
                                        store(signed_path_end_record)
                                        s.send_response(200)
                                        s.end_headers()
                                        return
                        print "no valid"
		except:
			pass
		s.send_response(500)
		s.end_headers()

if __name__ == '__main__':
	server_class = BaseHTTPServer.HTTPServer
	load_db()
	httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
	print time.asctime(), "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
	utils.redir_to_null()
	try:
                print "now serving!"
		httpd.serve_forever()
	except KeyboardInterrupt:
		store_db()
	httpd.server_close()
	print time.asctime(), "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)
