# Test case for rsa key transport (RSA-KEM)
''' 
Process : Sender generates a random secret key, encrypts it with receiver's RSA pk
and sends the ciphertext. The receiver decrypts it using their private key
'''
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from qunetsim.components import Host, Network
from qunetsim.objects import Message, Qubit, Logger
from qunetsim.backends import EQSNBackend
import time
import os
import hashlib
import hmac

# payload list
RSA_SYN = "RSA_SYN"
RSA_ACK = "RSA_ACK"
RSA_READY = "RSA_READY"
RSA_SEND_PK = "RSA_SEND_PK"
RSA_SEND_CT = "RSA_SEND_CT"
RSA_DONE = "RSA_DONE"

network = Network.get_instance()
backend = EQSNBackend()
results = {} # to keep results of each process' latency

# handshake req & response
def rsa_keyexchange_req(host, receiver_id, payload=RSA_SYN):
    # Request PQC key exchange
    print(host.host_id, " RSA_SYN -> ", receiver_id)
    # wait forever until ack received
    host.send_classical(receiver_id, payload, await_ack=True)
    return None

def rsa_keyexchange_rec(host, sender_id):
    msg = host.get_classical(sender_id, wait=10)
    if msg is None:
        return None
    for m in msg:
        if m.content == RSA_SYN:
            print(host.host_id, " RSA_ACK -> ", sender_id)
            print(RSA_READY)
        return None

# Key generation
# Generate a new RSA private key
def rsa_keygen(host, receiver_id):
    #start = time.perf_counter()
    private_key = rsa.generate_private_key(
        public_exponent=65537, # almost everyone uses 65537
        key_size=2048, 
    )
    # Get the corresponding public key
    public_key = private_key.public_key()
    #results['keygen_cpu'] = time.perf_counter() - start

    # store private key
    host.private_key = private_key
    
    # Send public key to another host so they can start encrypting
    alice_received_pk_start = time.perf_counter()
    host.send_classical(receiver_id, public_key, await_ack=True)
    result_name = 'pk_transmission ' + host.host_id + '<->' + receiver_id
    results[result_name] = time.perf_counter() - alice_received_pk_start
    

# Encryption
# encrypts a random secret key with receiver's pk
def rsa_encryption(host, receiver_id):
    public_key = host.get_classical(receiver_id, wait=5)[0].content
    #pk_bytes = bytes.fromhex(public_key) 
    #print("Pk byte count : ",pk_bytes)

    # Sender generates a random 32-byte session key or shared secret (SS) and encrypts it with Bob's PK
    ss1 = os.urandom(32) # in pqc, ss is calculated from complex math operations like NTT, INTT
    
    # Encrypt the symmetric key using RSA-OAEP
    # start = time.perf_counter() 
    encapsulated_key = public_key.encrypt(ss1,padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #results['encap_cpu'] = time.perf_counter() - start

    # Send encrypted msg to receiver
    bob_received_ct_start = time.perf_counter()
    host.send_classical(receiver_id, encapsulated_key.hex(), await_ack=True)
    
    result_name = 'ct_transmission ' + host.host_id + '<->' + receiver_id
    results[result_name] = time.perf_counter() - bob_received_ct_start
    return ss1

# Decryption
def rsa_decryption(host, receiver_id):
    ct = host.get_classical(receiver_id, wait=5)[0].content
    ct_bytes = bytes.fromhex(ct)
    print("Ct byte count : ",len(ct_bytes))

    # get host's private key
    private_key = host.private_key
    
    # Once we have an encrypted message, it can be decrypted using private key
    #start = time.perf_counter()
    ss2 = private_key.decrypt(
        ct_bytes, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #results['decap_cpu'] = time.perf_counter() - start
    return ss2

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
def rsa_handshake(host1, host2):
    # 1. handshake request & response
    rsa_keyexchange_req(host1, host2.host_id) 
    rsa_keyexchange_rec(host2, host1.host_id)

    # 2. keygen
    rsa_keygen(host2, host1.host_id)

    # 3. encrypt
    ss1 = rsa_encryption(host1, host2.host_id)

    # 4. decrypt
    ss2 = rsa_decryption(host2, host1.host_id)
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
    print("-- BEGINS RSA HANDSHAKE --")
    start = time.perf_counter()
    auth_result_ae, session_key_ae = rsa_handshake(alice, eva)
    results['rsa total handshake time'] = time.perf_counter() - start
    print("-- RSA LATENCY --")
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