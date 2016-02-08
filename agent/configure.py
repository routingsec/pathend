import Configuration
import utils
import netaddr
import auto_configuration_file
import urllib, json

as_configuration_line = "router bgp "

def read_configuration(bgp_router):
    if (Configuration.DEBUG):
        raw_cfg = file("BGP_config_example.txt").read()
        ip = json.loads(urllib.urlopen("http://ip.jsontest.com/").read())["ip"]
        raw_cfg = raw_cfg.replace("1.1.1.1",ip)
        return raw_cfg
    tn = utils.create_connection(bgp_router)
    tn.write("show running-config\n")
    config = tn.read(1024 * 1024)
    tn.write("exit\n")
    utils.close_connection(tn)
    return config

def is_beginning_config(l):
    return (l.find(as_configuration_line) >= 0)

def parse_out_as_number(l):
    data = l.split(" ")
    return int(data[2])
def end_of_context(l):
    return ((l.find("exit") >= 0) or is_beginning_config(l))
def is_neighbor(l):
    parts = l.split()
    if (len(parts) != 4):
        return False
    return ((parts[0] == "neighbor") and (parts[2] == "remote-as"))
def get_neighbor(l):
    parts = l.split()
    return int(parts[3])

def is_network(l):
    parts = l.split()
    if (len(parts) != 4):
        return False
    return ((parts[0] == "network") and (parts[2] == "mask"))
def get_network(l):
    parts = l.split()
    return netaddr.IPNetwork(parts[1] + "/" + parts[3])

def main():
    global as_configuration_line

    for bgp_router in Configuration.bgp_routers:
        config = read_configuration(bgp_router).split("\n")
        i = 0
        while (i < len(config)):
            if (is_beginning_config(config[i])):
                as_number = parse_out_as_number(config[i])
                i += 1
                neighbors = set()
                networks = set()
                while (not end_of_context(config[i])):
                    if (is_neighbor(config[i])):
                        neighbors.add(get_neighbor(config[i]))
                    elif (is_network(config[i])):
                        networks.add(get_network(config[i]))
                    i += 1
                auto_configuration_file.ASes[as_number] = (networks, neighbors)
            else:
                i += 1
