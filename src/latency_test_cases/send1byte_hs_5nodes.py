# -- SEND SMALL BYTES HANDSHAKE -- #
# Purpose : To compare bytes transmission latency with using pk and ct
# In this program, we just use a small byte as a msg to send to another party

# Written : 23/2/26

from qunetsim.components import Host, Network
from qunetsim.objects import Message, Qubit, Logger
from qunetsim.backends import EQSNBackend
import time
import oqs
import os
import random
import hashlib
import hmac

kem_name = "ML-KEM-768" # for kyber 768

# payload list
PQC_SYN = "PQC_SYN"
PQC_ACK = "PQC_ACK"
PQC_READY = "PQC_READY"
PQC_SEND_PK = "PQC_SEND_PK"
PQC_SEND_CT = "PQC_SEND_CT"
PQC_DONE = "PQC_DONE"

network = Network.get_instance()
backend = EQSNBackend()
results = {} # to keep results of each process' latency

def is_string(content):
    return isinstance(content, str)

def pqc_keyexchange_req(host, receiver_id, payload=PQC_SYN):
    # Request PQC key exchange
    print(host.host_id, " PQC_SYN -> ", receiver_id)
    # wait forever until ack received
    host.send_classical(receiver_id, payload, await_ack=True)
    return None

def pqc_keyexchange_rec(host, sender_id):
    msg = host.get_classical(sender_id, wait=10)
    if msg is None:
        return None
    for m in msg:
        if m.content == PQC_SYN:
            print(host.host_id, " PQC_ACK -> ", sender_id)
            print(PQC_READY)
        return None

# FOR PK -> BYTE = 1
def pqc_keygen(host, receiver_id):
    start = time.perf_counter()

    # Bob sends PK to Alice
    alice_received_pk_start = time.perf_counter()
    print(host.host_id, PQC_SEND_PK, " -> ", receiver_id)
    host.send_classical(receiver_id, "B", await_ack=True) # in qunetsim, they can only carry string msgs
    # time taken of Pk transmission
    result_name = 'pk_transmission ' + host.host_id + '<->' + receiver_id
    results[result_name] = time.perf_counter() - alice_received_pk_start
    return None

# FOR CT -> BYTE = 1
def pqc_encaps(host, receiver_id):
    msg = host.get_classical(receiver_id, wait=5)[0].content
    print("Received msg : ", msg)
    print("Byte count : ", len(msg))

    start = time.perf_counter() # start encaps
    bob_received_ct_start = time.perf_counter()
    host.send_classical(receiver_id,"A", await_ack=True) # sends ciphertext
    result_name = 'ct_transmission ' + host.host_id + '<->' + receiver_id
    results[result_name] = time.perf_counter() - bob_received_ct_start
    return None

# PQC decapsulation 
def pqc_decaps(host, receiver_id, kem_host):
    ct_msg = host.get_classical(receiver_id, wait=5)[0].content
    print("Received msg : ", ct_msg)
    print("Byte count : ", len(ct_msg))
    return None

def pqc_handshake(host1, host2):
    # initiate PQC key exchange request/response
    pqc_keyexchange_req(host1, host2.host_id) 
    pqc_keyexchange_rec(host2, host1.host_id)

    # 1) host2 sgenerates a public, private key pair and sends public key to host1
    #t_keygen_start = time.time()
    pqc_keygen(host2, host1.host_id) # gets host2's sk
 
    # 2) host1 encapsulates and sends ciphertext -> host2 gets ciphertext
    #t_encap_start = time.time()
    pqc_encaps(host1, host2.host_id)
  
    # 3) host2 decapsulates -> get shared secret
    #t_decap_start = time.time()
    pqc_decaps(host2, host1.host_id, None) # uses host2's kem object
    #t_decap_end = time.time()

    return None

def main():
    nodes = ["Alice", "Bob", "Cathy", "Dave", "Eva"]
    network.start(nodes)

    # create host objects
    alice = Host("Alice")
    bob = Host("Bob")
    cathy = Host("Cathy")
    dave = Host("Dave")
    eva = Host("Eva")

    # add connections
    alice.add_connection("Bob")
    bob.add_connection("Alice")
    cathy.add_connection("Bob")
    bob.add_connection("Cathy")
    cathy.add_connection("Dave")
    dave.add_connection("Cathy")
    dave.add_connection("Eva")
    eva.add_connection("Dave")

    alice.start()
    bob.start()
    cathy.start()
    dave.start()
    eva.start()
    network.add_hosts([alice, bob, cathy, dave, eva])

    # start PQC handshake session after request
    print("-- BEGINS 1 BYTE HANDSHAKE --")
    t0 = time.time()
    pqc_handshake(alice, eva)
    t1 = time.time()
    print("-- 1 BYTE LATENCY --")
    for key in results.keys():
        print(key + " : " + str(results.get(key)))
    # print("PQC Overall Handshake Time: ", t1 - t0)
    print("\n")

if __name__ == '__main__':
    main()