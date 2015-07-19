import netaddr

class certification_request:
	def __init__(self, public_key, as_number, network):
		self.public_key = public_key
		self.network = network
		self.as_number = as_number

class challenge:
	def __init__(self, challenge, real_dest, as_number, network):
		self.challenge = challenge
		self.real_dest = real_dest
		self.as_number = as_number
		self.network = network

class response:				
	def __init__(self, public_key, as_number, network, challenge, real_src):
		self.public_key = public_key
		self.as_number = as_number
		self.network = network
		self.challenge = challenge
		self.real_src = real_src

class signature:
	def __init__(self, sig):
		self.sig = sig

class signed_RPKI_cert:																				
	def __init__(self, certification, signatures, links, signature_for_links):
		self.certification = certification
		self.signatures = signatures
		self.links = links
		self.signature_for_links = signature_for_links
		
