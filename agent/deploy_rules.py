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

cached_rules = None
ASKED_TO_STOP = False
DeployerThread = LocalThreads.ThreadPool(1)
tab_ctx = 0

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
		for prefix in db.keys():
			if (not utils.verify_path_end_record(db[prefix])):
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
	s = "["
	for n in neighbors:
		s += str(n) + ","
	if (s[-1] == ","):
		s = s[:-1]
	s += "]"
	return s

def whitelist_prefix(record):
	rule_id = str(record.certification.as_number) + "-whitelist" #+ str(int(random.random() * 10000))
	for bgp_router in Configuration.bgp_routers:
		tn = utils.create_connection(bgp_router)
		deploy_rule(tn, "as-path access-list orig-as" + rule_id + " permit ^"+ str(record.certification.as_number) +"$")
		deploy_rule(tn, "ip as-path access-list adj-as" + rule_id + " permit "+ str(record.certification.as_number) + "_" + encode_neighbors(record.links) +"$")
		deploy_rule(tn, "route-map Protect_AS" + rule_id + " permit 1")
		deploy_rule(tn, "match rpki valid")
		max_address_size_bits = "32"
		if (not record.certification.network.ipv6):
			max_address_size_bits = "128"
		deploy_rule(tn, "match ip address prefix-list " + str(record.certification.network) + " le " + max_address_size_bits)
		deploy_rule(tn, "match ip as-path orig-as" + rule_id)
		deploy_rule(tn, "match ip as-path adj-as" + rule_id)
		deploy_rule(tn, "exit")
		utils.close_connection(tn)
		
def deploy_blacklist_rules():
	for bgp_router in Configuration.bgp_routers:
		tn = utils.create_connection(bgp_router)
		deploy_rule(tn, "route-map BGP_Allow_Legacy permit 2")
		deploy_rule(tn, "match rpki not-found")
		deploy_rule(tn, "exit")
		utils.close_connection(tn)

	for bgp_router in Configuration.bgp_routers:
		tn = utils.create_connection(bgp_router)
		deploy_rule(tn, "route-map BGP_Filter_Deny_All deny 3")
		deploy_rule(tn, "exit")	
		utils.close_connection(tn)

def setup():
	my_ip = netifaces.ifaddresses('eth0')[2][0]['addr']
	for bgp_router in Configuration.bgp_routers:
		tn = utils.create_connection(bgp_router)
		for as_number in Configuration.ASes.keys():
			deploy_rule(tn, "router bgp " + str(as_number))
			deploy_rule(tn, "bgp rpki server tcp " + my_ip + " port 32002 refresh " + str(Configuration.UPDATE_INTERVAL))
			deploy_rule(tn, "exit")
	deploy_blacklist_rules()

def deploy_new_rules():
	global cached_rules
	for record in cached_rules.keys():
		whitelist_prefix(cached_rules[record])
	
def backgroud_updates():
	global cached_rules
	load_db()
	for i in xrange(10):
		try:
			if (cached_rules == None):
				download_from_random_db()
				break
		except:
			pass

	setup()
	i = 0
	download_from_random_db()
	deploy_new_rules()
	while(not ASKED_TO_STOP):
		time.sleep(1)
		i += 1
		if (i == UPDATE_INTERVAL):
			deploy_new_rules()
			download_from_random_db()
			i = 0

def exit():
	global ASKED_TO_STOP
	ASKED_TO_STOP = True
	DeployerThread.wait_completion()

def main():
	DeployerThread.add_task(backgroud_updates)
