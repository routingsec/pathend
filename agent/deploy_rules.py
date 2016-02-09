import httplib, urllib
import pickle
import zlib
import time
import netifaces
import LocalThreads
import random
import Configuration
import protocol_messages
import utils
import RPKI

cached_rules = None
ASKED_TO_STOP = False
tab_ctx = 0

gRPKITree = None

def download_from_random_db():
	db_server = random.choice(Configuration.StorageServer)
	download_rules(db_server)

def load_db():
	global cached_rules
	try:
		dbfile = file(Configuration.PREFIX_DB_FILE, "r")
		cached_rules = pickle.load(dbfile)
	except:
		pass

def store_db():
	global cached_rules
	dbfile = file(Configuration.PREFIX_DB_FILE, "w")
	pickle.dump(cached_rules, dbfile)

def download_rules(prefix_db):
	global cached_rules
	print "++++ Updating from prefix-DB... ++++"
	conn = httplib.HTTPConnection(prefix_db, 8080)
	# post the request to initiate the prefix-ownership procedure.
	conn.request("GET", "/all")
	
	# wait for the response...
	response = conn.getresponse()
	# prefix-ownership authentication procedure completed
	if (response.status == 200):
		db = pickle.loads(zlib.decompress(response.read()))
		for asn in db:
                        record = db[asn].get()
                        authorized_pubkeys = gRPKITree.get_pub_key_set(asn)
                        verified = False
                        for pubkey in authorized_pubkeys:
                                if (utils.verify(signed_record.record, signed_record.signature, pubkey)):
                                        verified = True
                                        break
                        if not verified:
				del db[prefix]
		cached_rules = db
		store_db()
	else:
		print response.status

def deploy_rule(tn, rule):
	global tab_ctx
	if (Configuration.DEBUG):
		print tab_ctx * "\t" + rule
		if (rule.startswith("router bgp")) or (rule.startswith("route-map")):
			tab_ctx += 1
		if (rule.startswith("exit")):
			tab_ctx -= 1
		if (tab_ctx < 0):
			tab_ctx = 0
		return
	tn.write(rule + "\n")

def encode_neighbors(neighbors):
	s = ")"
	for n in neighbors:
		s += str(n) + "|"
	if (s[-1] == "|"):
		s = s[:-1]
	s += "("
	return s

gSetupRules = {}
def deploy_record(raw_record):
        record = raw_record.get()
	rule_id = "as" + str(record.asn)
	record_rule_ids[rule_id] = time.time()
	for bgp_router in Configuration.bgp_routers.keys():
		tn = utils.create_connection(bgp_router)
		deploy_rule(tn, "ip as-path access-list " + rule_id + " deny " + "_[^" + encode_neighbors(record.links) + "]_" + str(record.asn) + "_")
		if not record.transient_flag:
                        deploy_rule(tn, "ip as-path access-list " + rule_id + " deny _" + str(record.asn) + "_[0-9]+_")
		deploy_rule(tn, "exit")
		utils.close_connection(tn)

def deploy_allow_all_rule():
	for bgp_router in Configuration.bgp_routers.keys():
		tn = utils.create_connection(bgp_router)
		deploy_rule(tn, tn, "ip as-path access-list allow-all permit")
        

def update_rules():
        global gSetupRules        
	for bgp_router in Configuration.bgp_routers.keys():
		tn = utils.create_connection(bgp_router)
		deploy_rule(tn, "route-map Path-End-Validation permit 1")
		for rule_id in gSetupRules:
                        deploy_rule(tn, "match ip as-path " + rule_id)
                deploy_rule(tn, "match ip as-path allow-all")
		deploy_rule(tn, "exit")
		utils.close_connection(tn)

def deploy_new_rules():
	global cached_rules
	for record in cached_rules.keys():
		deploy_record(cached_rules[record])
	update_rules()
	
def backgroud_updates():
	global cached_rules
	deploy_allow_all_rule()
	load_db()
	for i in xrange(10):
		try:
			if (cached_rules == None):
				download_from_random_db()
				break
		except:
			pass

	deploy_allow_all_rule()
	i = 0
	download_from_random_db()
	deploy_new_rules()
	while True:
		time.sleep(1)
		i += 1
		if (i == Configuration.UPDATE_INTERVAL):
			deploy_new_rules()
			download_from_random_db()
			i = 0

def main():
        global gRPKITree
        gRPKITree = RPKI.RPKITree()
        backgroud_updates()
