import utils
import pickle
import time

class PathEndRecord(object):
    def __init__(self, asn, links, transient_flag):
        self.asn = asn
        self.links = links
        self.transient_flag = transient_flag
        self.timestamp = time.time()

class SignedPathEndRecord:
    def __init__(self, asn, links, transient_flag):
        self.record = pickle.dumps(PathEndRecord(asn, links, transient_flag))
        self.signature = utils.sign(self.record)
    def get(self):
        return pickle.loads(self.record)
    def verify_path_end_record(self, pubkey):
        verify(self.record, self.signature, pubkey)
