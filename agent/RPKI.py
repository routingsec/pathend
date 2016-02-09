import interval
import gzip
import cPickle
import json
import utils
import time

kRPKIDataDir = "RPKI_data"

class RPKICertificate:
    def __init__(self, d, parent = None):        
        self.resources = []
        self.children = []
        self.parent = parent
        self.ASes = interval.IntervalSet()
        self.public_key = self.__parse_pk(d["public_key"])

        for resource in d["resources"]:
            if resource.startswith("AS"):
                begin_int = 0
                end_int = 0
                if ("-" in resource):
                    begin, end = resource.split("-")
                    begin_int = int(begin.replace("AS",""))
                    end_int = int(end.replace("AS",""))
                else:
                    begin_int = int(resource.replace("AS",""))
                    end_int = begin_int
                self.ASes.add(interval.Interval(begin_int, end_int))

        for child in d["children"]:
            if (child["type"] == "cer"):
                self.children.append(RPKICertificate(child["child"], self))

    def get_pks(self, asn, pk_set):
        if asn in self.ASes:
            pk_set.add(self.public_key)
        for child in self.children:
            child.get_pks(asn, pk_set)

    @staticmethod
    def __parse_pk(s):
        info, modulus, exponenet = s.split("\n")
        if "RSA" not in info:
            return None
        
        modulus_i = modulus.find("modulus: ")
        if modulus_i < 0:
            return None
        exponent_i = exponenet.find("public exponent: ")
        if exponent_i < 0:
            return None
        n = int(modulus[modulus_i + len("modulus: "):].replace(" ",""))
        e = int(exponenet[exponent_i + len("public exponent: "):].replace(" ", ""))
        return utils.pub_key_from_ints(e, n)
        
            
RIRs = ["AFRINIC", "APNIC_AFRINIC", "APNIC_ARIN", "APNIC_IANA", "APNIC_LACNIC", "APNIC_RIPE", "ARIN", "LACNIC", "RIPE"]
class RPKITree:
    def __init__(self):
        self.rpki_trees = {}
        for rir in RIRs:
            print time.time(), "processing", rir
            self.rpki_trees[rir] = RPKITree.__parse_certs(rir)

    def get_pub_key_set(self, asn):
        key_set = set()
        for rir in self.rpki_trees:
            self.rpki_trees[rir].get_pks(asn, key_set)
        return key_set

    ###### Private buildup methods
    @staticmethod
    def __parse_certs(rir_file):
        try:
            f = gzip.open("RPKI-tree/" + rir_file + ".pickle", "rb")
            data = cPickle.load(f)
            f.close()
            return data
        except:
            pass

        begin_t = time.time()
        f = file(kRPKIDataDir + "/" + rir_file, "r")
        d = json.load(f)["trustAnchor"]
        cert_tree = RPKICertificate(d)
        f.close()
        return cert_tree
