# Elliptic-curve Diffie–Hellman (ECDH) handshake
'''
It is a key-agreement protocol used to establish a shared secret over an insecure channel
libary : cryptography
'''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from qunetsim.components import Host, Network
from qunetsim.objects import Message, Qubit, Logger
from qunetsim.backends import EQSNBackend
import time
import oqs
import os
import hashlib
import hmac

# payload list
ECDH_SYN = "ECDH_SYN"
ECDH_ACK = "ECDH_ACK"
ECDH_READY = "ECDH_READY"
ECDH_SEND_PK = "ECDH_SEND_PK"
ECDH_SEND_CT = "ECDH_SEND_CT"
ECDH_DONE = "ECDH_DONE"

network = Network.get_instance()
backend = EQSNBackend()
results = {} # to keep results of each process' latency

# handshake req & response
def ecdh_keyexchange_req(host, receiver_id, payload=ECDH_SYN):
    # Request PQC key exchange
    print(host.host_id, " ECDH_SYN -> ", receiver_id)
    # wait forever until ack received
    host.send_classical(receiver_id, payload, await_ack=True)
    return None

def ecdh_keyexchange_rec(host, sender_id):
    msg = host.get_classical(sender_id, wait=5)
    if msg is None:
        return None
    for m in msg:
        if m.content == ECDH_SYN:
            print(host.host_id, " ECDH_ACK -> ", sender_id)
            print(ECDH_READY)
        return None

# 1. Generate key pairs. Both alice and bob generate their own pairs
# Then Alice sends her public_key to Bob, 
# and Bob sends his public_key to Alice.
def ecdh_keygen(host, receiver_id):
    #start = time.perf_counter()
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    #results['keygen_cpu'] = time.perf_counter() - start

    # host store private key
    host.private_key = private_key

    host_id = host.host_id
    
    # Send public key to another host so they can start encrypting
    received_pk_start = time.perf_counter()
    host.send_classical(receiver_id, public_key, await_ack=True)
    result_name = 'pk_transmission ' + host.host_id + '<->' + receiver_id
    results[result_name] = time.perf_counter() - received_pk_start

# 2. Both of them compute the shared secret using their own private keys
def ecdh_compute_ss(host, receiver_id):
    public_key = host.get_classical(receiver_id, wait=5)[0].content

    # gets its own private key
    private_key = host.private_key

    # computes ss using their private key + another node's public key
    #start = time.perf_counter() 
    ss = private_key.exchange(ec.ECDH(), public_key)
    #results['compure_ss_cpu'] = time.perf_counter() - start
    return ss

def mac_auth(ss_host, ss_receiver, host, receiver):
    test_msg = "AUTH_CHECK" # msg to authenticate, optional

    # creates new HMAC object 
    tag = hmac.new(ss_host, test_msg.encode(), hashlib.sha256).digest()
    
    # Alice sends [Message + Tag(HMAC)] to Bob
    # structure : Message | HMAC
    host.send_classical(receiver.host_id, test_msg + "|" + tag.hex(), await_ack=True)
    
    # Bob gets the classical messages (one contains the hashed shared secret)
    messages = receiver.get_classical(host.host_id, wait=5)

    if not messages:
        print("Error: No messages received for MAC auth")
        return False
    
    auth_success = False
    # Look for the msg that actually contains the seperator (which is message+tag)
    for m in messages:
        content = m.content
        if "|" in content:
            try:
                msg_content, msg_tag = content.split("|")
                # hash using bob's ss
                expected_tag = hmac.new(ss_receiver, msg_content.encode(), hashlib.sha256).digest()
                
                if hmac.compare_digest(expected_tag, bytes.fromhex(msg_tag)):
                    print("MAC Verification Successful!")
                    auth_success = True
                    break
            except ValueError:
                continue # Skip messages that don't fit the format
   
    return auth_success # boolean

# Handshake
def ecdh_handshake(host1, host2):
    # 1. handshake request & response
    ecdh_keyexchange_req(host1, host2.host_id) 
    ecdh_keyexchange_rec(host2, host1.host_id)

    # 2. keygen
    ecdh_keygen(host2, host1.host_id)
    ecdh_keygen(host1, host2.host_id)

    # 3. encrypt
    ss1 = ecdh_compute_ss(host1, host2.host_id)
    ss2 = ecdh_compute_ss(host2, host1.host_id)

    # 4. decrypt
    print("Alice SS:", ss1.hex())
    print("Bob   SS:", ss2.hex())

    if(ss1==ss2):
        print("PQC Handshake Successful! Shared secrets match,")
        print("MATCH:", ss1 == ss2)
        print("\n")
    else:
         print("Failure: Shared secrets do not match!")

    auth_result = mac_auth(ss1,ss2,host1,host2)
    print("Auth result = " ,auth_result)
    print("\n")
    if auth_result:
        print("-- STORING SESSION KEY --")
        host1.session_key = ss1
        host2.session_key = ss2
        print(f"Session key stored for {host1.host_id} <-> {host2.host_id}")
        print("\n")
        return True, ss1 # Return both the status and the key
    return False, None

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

    # start ECDH handshake session after request
    print("-- BEGINS ECDH HANDSHAKE --")
    start = time.perf_counter()
    auth_result_ae, session_key_ae = ecdh_handshake(alice, eva)
    results['ecdh total handshake time'] = time.perf_counter() - start
    print("-- ECDH LATENCY --")
    for key in results.keys():
        print(key + " : " + str(results.get(key)))
    print("\n")

    if auth_result_ae:
        print("--- READY FOR QUANTUM OPERATIONS ---")
        # Example: Using the key for a secure entanglement request
        # send_secure_entanglement_request(alice, "Bob", session_key)
    else:
        print("Handshake failed. Aborting.")

    network.draw_classical_network()

if __name__ == '__main__':
    main()