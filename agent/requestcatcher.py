import nfqueue
import pickle
import threading
from LocalThreads import *
import os
import socket
import netaddr
import time
import subprocess
from multiprocessing import Process
from scapy.all import IP
from scapy.all import TCP
from scapy.all import packet
import sys

MSG_QUEUE_NUM = 14
queue_users = 0
responderNFQ = None
handling_pool = ThreadPool(1)
#lock = threading.RLock()
Processes = []

def handle_packets():
    global responderNFQ
    try:
        responderNFQ.try_run()
    except:
        print "done handling packets"
    return 0

handler_thread = threading.Thread(target = handle_packets)

def handle_challenge_responses(source_port):
    global responderNFQ
    global handling_pool
    global queue_users

    set_responding_rule(source_port)
    # start handling packets
    if (queue_users == 0):
        print "creating queue"
        responderNFQ = nfqueue.queue()
        responderNFQ.set_callback(source_fix)
        responderNFQ.fast_open(MSG_QUEUE_NUM, socket.AF_INET)
        p = Process(target = handle_packets)
        Processes.append(p)
        #handler_thread.start()
        p.start()
        time.sleep(1)
        print "finished"
    queue_users += 1

    print "initialization done"

def delete_responding_rule(source_port):
#       global lock
    global queue_users

    rule = "OUTPUT -p tcp --source-port " + str(source_port) + " -j NFQUEUE --queue-num " + str(MSG_QUEUE_NUM)
    os.system("iptables -D " + rule)
#       lock.acquire()
    queue_users -= 1
    if (queue_users == 0):
#               lock.release()
        responderNFQ.unbind(socket.AF_INET)
        responderNFQ.close()
        for p in Processes:
            p.terminate()
#       else:
#               lock.release()

def source_fix(dummy, this_packet):
    """
    Called when a PnPIPsec message arrives to handle the message.
    """
    print "source_fix"
    # parse the message and its type
    pkt = IP(this_packet.get_data())
    #print "+++++++++++++++++++++++++++++++++"
    #print pkt.show()
    #print "+++++++++++++++++++++++++++++++++"
    #print "---------------------------------"
    if (type(pkt[TCP].payload) is not packet.NoPayload):
        response = pickle.loads(str(pkt[TCP].payload))
        print "changing source to ", response.real_src
        print dir(pkt)
        pkt.src = response.real_src
    this_packet.set_verdict(nfqueue.NF_ACCEPT)

def set_responding_rule(source_port):
    rule = "OUTPUT -p tcp --source-port " + str(source_port) + " -j NFQUEUE --queue-num " + str(MSG_QUEUE_NUM)
    os.system("iptables -A " + rule)
