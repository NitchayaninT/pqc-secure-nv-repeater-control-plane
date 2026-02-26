# Testing PQC integration with QuNetSim
# Insert a handshake step before allowing an entanglement request
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

# PQC Key generation
def pqc_keygen(host, receiver_id):
    #start = time.perf_counter()
    # This kem_receiver will hold the secret key internally, which will be used in decapsulation
    kem_receiver = oqs.KeyEncapsulation(kem_name)  
    pk = kem_receiver.generate_keypair()
    # Time taken of key generation process (computational latency)
    #results['keygen_cpu'] = time.perf_counter() - start

    # Bob sends PK to Alice
    alice_received_pk_start = time.perf_counter()
    print(host.host_id, PQC_SEND_PK, " -> ", receiver_id)
    host.send_classical(receiver_id, pk.hex(), await_ack=True) # in qunetsim, they can only carry string msgs

    # time taken of Pk transmission
    result_name = 'pk_transmission ' + host.host_id + '<->' + receiver_id
    results[result_name] = time.perf_counter() - alice_received_pk_start
    print("PQC_SEND_PK_ACK received")
    return kem_receiver

# PQC encapsulation
def pqc_encaps(host, receiver_id):
    pk_msg = host.get_classical(receiver_id, wait=5)[0].content
    pk_bytes = bytes.fromhex(pk_msg) # because we sent hex string
    print("Byte count = ",len(pk_bytes))

    #start = time.perf_counter() # start encaps
    with oqs.KeyEncapsulation(kem_name) as kem:
        ct, ss_enc = kem.encap_secret(pk_bytes) # only accept a byte type object
        
        # calculate encaps computation time
        #results['encap_cpu'] = time.perf_counter() - start

        # sends ct back to bob
        print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
        bob_received_ct_start = time.perf_counter()
        host.send_classical(receiver_id,ct.hex(), await_ack=True) # sends ciphertext

        result_name = 'ct_transmission ' + host.host_id + '<->' + receiver_id
        results[result_name] = time.perf_counter() - bob_received_ct_start
        print("PQC_CT_ACK received")
    return ss_enc # alice gets their shared secret from bob's pk

# PQC decapsulation 
def pqc_decaps(host, receiver_id, kem_host):
    ct_msg = host.get_classical(receiver_id, wait=5)[0].content
    ct_bytes = bytes.fromhex(ct_msg)
    print("Byte count = ",len(ct_bytes))

    #start = time.perf_counter()
     
    with oqs.KeyEncapsulation(kem_name) as kem:
        # uses bob's internal private key to decap the received ciphertext
        ss_dec = kem_host.decap_secret(ct_bytes)

        # calculates decap computation time
        #results['decap_cpu'] = time.perf_counter() - start
        print(PQC_DONE)
        
    return ss_dec

# mac is used to verify data integrity and authenticity of a message
# by combining a secret key with a cryptographic hash function (SHA-256)
# kyber ensures no one can read the message
# hmac ensures no one has changed it or faked it
# hmac proves that the message has not been altered in transit
# hmac is also used to wrap a msg being sent 
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

def pqc_handshake(host1, host2):
    # initiate PQC key exchange request/response
    pqc_keyexchange_req(host1, host2.host_id) 
    pqc_keyexchange_rec(host2, host1.host_id)

    # 1) host2 sgenerates a public, private key pair and sends public key to host1
    #t_keygen_start = time.time()
    host2_kem = pqc_keygen(host2, host1.host_id) # gets host2's sk
 
    # 2) host1 encapsulates and sends ciphertext -> host2 gets ciphertext
    #t_encap_start = time.time()
    ss1 = pqc_encaps(host1, host2.host_id)
  
    # 3) host2 decapsulates -> get shared secret
    #t_decap_start = time.time()
    ss2 = pqc_decaps(host2, host1.host_id, host2_kem) # uses host2's kem object
    #t_decap_end = time.time()
    print(host1.host_id +" SS:", ss1.hex())
    print(host2.host_id +" SS:", ss2.hex())

    if (ss1 == ss2):
        print("PQC Handshake Successful! Shared secrets match,")
        print("MATCH:", ss1 == ss2)
        print("\n")
    else:
         print("Failure: Shared secrets do not match!")

    # to prove that the PQC handshake is successful and both sides actually have the same key
    # its better than trading shared secret across the internet because thats risky!
    auth_result = mac_auth(ss1,ss2,host1,host2)
    print("Auth result = " ,auth_result)
    print("\n")
    if auth_result:
        # Store the SESSION key (shared secret) inside the host objects for future use
        # this is to use HMAC to wrap with a msg
        # since qunetsim doesnt have the function to add session key, in python, we can add new attributes
        # to an object even if they arent in original class
        print("-- STORING SESSION KEY --")
        host1.session_key = ss1
        host2.session_key = ss2
        print(f"Session key stored for {host1.host_id} <-> {host2.host_id}")
        print("\n")
        return True, ss1 # Return both the status and the key
    return False, None

def main():
    nodes = ["Alice", "Bob", "Cathy"]
    network.start(nodes)

    # create host objects
    alice = Host("Alice")
    alice.add_connection("Bob")
    bob = Host("Bob")
    bob.add_connection("Alice")
    cathy = Host("Cathy")
    cathy.add_connection("Bob")
    bob.add_connection("Cathy")

    alice.start()
    bob.start()
    cathy.start()
    network.add_hosts([alice, bob, cathy])

    # start PQC handshake session after request
    # for multinode, try doing handshake for every single link since we want to see how long it takes for all nodes to finish the handshake
    print("-- BEGINS PQC HANDSHAKE FOR EVERY NODE--")
    t0 = time.perf_counter()
    auth_result_ab, session_key_ab = pqc_handshake(alice, bob)
    auth_result_bc, session_key_bc = pqc_handshake(bob, cathy)
    auth_result_ac, session_key_ac = pqc_handshake(alice,cathy) # not adjacent
    t1 = time.perf_counter()
    print("-- PQC LATENCY --")
    for key in results.keys():
        print(key + " : " + str(results.get(key)))
    print("PQC Overall Handshake Time: ", t1 - t0)
    print("\n")

    if auth_result_ab & auth_result_ac & auth_result_bc:
        print("--- READY FOR QUANTUM OPERATIONS ---")
        # Example: Using the key for a secure entanglement request
        # send_secure_entanglement_request(alice, "Bob", session_key)
    else:
        print("Handshake failed. Aborting.")

    network.draw_classical_network()

if __name__ == '__main__':
    main()