# Testing PQC integration with QuNetSim
# Insert a handshake step before allowing an entanglement request
from qunetsim.components import Host, Network
from qunetsim.objects import Message, Qubit, Logger
from qunetsim.backends import EQSNBackend
import time
import oqs
import os
import random

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

# PQC Key generation
def pqc_keygen(host, receiver_id):
    # This kem_receiver will hold the secret key internally, which will be used in decapsulation
    kem_receiver = oqs.KeyEncapsulation(kem_name)  
    pk = kem_receiver.generate_keypair()
    print(host.host_id, PQC_SEND_PK, " -> ", receiver_id)
    host.send_classical(receiver_id, pk.hex(), await_ack=True) # in qunetsim, they can only carry string msgs
    return kem_receiver

def pqc_encaps(host, receiver_id):
    pk = host.get_classical(receiver_id)
    if pk is None:
        raise RuntimeError(host.host_id+" did not receive PK")
    for m in pk:
        m = bytes.fromhex(m.content) # because we sent hex string
        with oqs.KeyEncapsulation(kem_name) as kem:
            ct, ss_enc = kem.encap_secret(m) # only accept a byte type object
            print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
            host.send_classical(receiver_id,ct.hex(), await_ack=True) # sends ciphertext
            # print("PQC_CT_ACK received")
            break
    return ss_enc # alice gets their shared secret from bob's pk

def pqc_decaps(host, receiver_id, kem_host):
    ct = host.get_classical(receiver_id)
    if ct is None:
        raise RuntimeError(host.host_id+" did not receive Ciphertext")
    for m in ct:
        m = bytes.fromhex(m.content)
        with oqs.KeyEncapsulation(kem_name) as kem:
             # uses bob's internal private key to decap the received ciphertext
            ss_dec = kem_host.decap_secret(m)
            print(PQC_DONE)
            break
    return ss_dec

def pqc_handshake(host1, host2):
    # initiate PQC key exchange request/response
    pqc_keyexchange_req(host1, host2.host_id) 
    pqc_keyexchange_rec(host2, host1.host_id)

    # 1) host2 sgenerates a public, private key pair and sends public key to host1
    t_keygen_start = time.time()
    host2_kem = pqc_keygen(host2, host1.host_id) # gets host2's sk
    t_keygen_end = time.time()
    print("PQC Keygen Time (+ACK): ", t_keygen_end - t_keygen_start)

    # 2) host1 encapsulates and sends ciphertext -> host2 gets ciphertext
    t_encap_start = time.time()
    ss1 = pqc_encaps(host1, host2.host_id)
    t_encap_end = time.time()
    print("PQC Encapsulation Time(+ACK): ", t_encap_end - t_encap_start)

    # 3) host2 decapsulates -> get shared secret
    t_decap_start = time.time()
    ss2 = pqc_decaps(host2, host1.host_id, host2_kem) # uses host2's kem object
    t_decap_end = time.time()
    print("PQC Decapsulation Time: ", t_decap_end - t_decap_start)

    print("Alice SS:", ss1.hex())
    print("Bob   SS:", ss2.hex())

    if (ss1 == ss2):
        print("PQC Handshake Successful! Shared secrets match,")
        print("MATCH:", ss1 == ss2)
    else:
         print("Failure: Shared secrets do not match!")

    return ss1 # In kyber, shared secret is designed to be session key bytes
    # Reason : they're secure and can only be known by them

def main():
    nodes = ["Alice", "Bob"]
    network.start(nodes)

    # create host objects
    alice = Host("Alice")
    alice.add_connection("Bob")
    bob = Host("Bob")
    bob.add_connection("Alice")

    alice.start()
    bob.start()
    network.add_hosts([alice, bob])

    # start PQC handshake session after request
    t0 = time.time()
    session_key = pqc_handshake(alice, bob)
    t1 = time.time()
    print("PQC Handshake Time: ", t1 - t0)
    print("session key = ", session_key)

if __name__ == '__main__':
    main()