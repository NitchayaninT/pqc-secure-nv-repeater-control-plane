# Test case for rsa key transport (RSA-KEM)
''' 
Process : Sender generates a random secret key, encrypts it with receiver's RSA pk
and sends the ciphertext. The receiver decrypts it using their private key
'''
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import oqs
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

sign_algo = "ML-DSA-44" #post-quantum digital signature scheme

network = Network.get_instance()
backend = EQSNBackend()
results = {} # to keep results of each process' latency

def generate_long_term_sig_keys():
    with oqs.Signature(sign_algo) as sig:
        pub = sig.generate_keypair()
        sk = sig.export_secret_key()
    return pub, sk

 # generate long term "signature keys" for Bob
bob_pk, bob_sk = generate_long_term_sig_keys()

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
    start = time.perf_counter()
    private_key = rsa.generate_private_key(
        public_exponent=65537, # almost everyone uses 65537
        key_size=2048, 
    )
    # Get the corresponding public key
    public_key = private_key.public_key()
    results['keygen_cpu'] = time.perf_counter() - start

    # store private key
    host.private_key = private_key
    pk_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Send public key to another host so they can start encrypting
    alice_received_pk_start = time.perf_counter()
    host.send_classical(receiver_id, pk_bytes.hex())
    results['pk_transmission'] = time.perf_counter() - alice_received_pk_start
    print(" -- Alice received pk -- ")
    host.pk = pk_bytes.hex()
    
# Encryption
# encrypts a random secret key with receiver's pk
def rsa_encryption(host, receiver_id):
    msg = host.get_classical(receiver_id, wait=5)[0].content # not public key object, just bytes
    while(msg.startswith("RSA_SYN")):
        print("Alice's pk hasnt arrived to Bob yet. Waiting for pk...")
        msg = host.get_classical(receiver_id, wait=5)[0].content
    #assert msg.startswith("PK|")
    pk_bytes = bytes.fromhex(msg)
    
    print("Pk byte count : ",len(pk_bytes))

    # Load the public key from bytes
    public_key = serialization.load_der_public_key(pk_bytes)

    # Sender generates a random 32-byte session key or shared secret (SS) and encrypts it with Bob's PK
    ss1 = os.urandom(32) # in pqc, ss is calculated from complex math operations like NTT, INTT
    
    # Encrypt the symmetric key using RSA-OAEP
    start = time.perf_counter() 
    encapsulated_key = public_key.encrypt(ss1,padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    results['encap_cpu'] = time.perf_counter() - start

    # get bob's signed pk, sk is in global
    # Signs handshake transcript (all previous messages) with the private signature key
    transcript = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) + encapsulated_key # in a real implementation, this would include all previous handshake messages, but for simplicity we just use pk and ct
    transcript_hash = hashlib.sha256(transcript).digest()
    
     # Use Bob's private "signature" key to sign to get CertificateVerify
    with oqs.Signature(sign_algo, secret_key=bob_sk) as signer:
        sig_B = signer.sign(transcript_hash) 

    # Send encrypted msg to receiver
    bob_received_ct_start = time.perf_counter()
    host.send_classical(receiver_id, encapsulated_key.hex() + "|" + sig_B.hex() + "|" + bob_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (bob's signature key) together
    results['ct_transmission'] = time.perf_counter() - bob_received_ct_start
    return ss1

# Decryption
def rsa_decryption(host, receiver_id):
    ct = host.get_classical(receiver_id, wait=5)[0].content
    ct_hex, sig_hex, bob_pk_hex = ct.split("|")
    ct_bytes = bytes.fromhex(ct_hex)
    sig_bytes = bytes.fromhex(sig_hex)
    bob_pk_bytes = bytes.fromhex(bob_pk_hex)
    print("Ct byte count : ",len(ct_bytes))

    # Verify the signature using Bob's public key to authenticate that the message is indeed from Bob and has not been tampered with
    transcript = bytes.fromhex(host.pk) + ct_bytes # record of the messages being sent
    transcript_hash = hashlib.sha256(transcript).digest()

    with oqs.Signature(sign_algo) as verifier:
        if verifier.verify(transcript_hash, sig_bytes, bob_pk_bytes):
            print("Signature verification successful! Message is authenticated and has not been tampered with.")
        else:
            print("Signature verification failed! Message may have been tampered with or is not from the expected sender.")
            return None 

    # get host's private key
    private_key = host.private_key
    
    # Once we have an encrypted message, it can be decrypted using private key
    start = time.perf_counter()
    ss2 = private_key.decrypt(
        ct_bytes, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    results['decap_cpu'] = time.perf_counter() - start
    return ss2

# after handshake, Alice can send a message to Bob with HMAC 
def send_finished(host, receiver_id, ss):
    ss_hashed = hashlib.sha256(b"VERIFY_SS" + ss).digest()
    finished = hmac.new(ss_hashed, b"VERIFY_SS", hashlib.sha256).digest()
    host.send_classical(receiver_id, "FIN|" + finished.hex(), await_ack=True)

# then Bob can verify whether the shared secret is the same by comparing the received HMAC with the expected HMAC using the shared secret he has
def verify_finished(host, peer_id, ss) -> bool:
    msg = host.get_classical(peer_id, wait=5)[0].content
    if not msg.startswith("FIN|"):
        return False
    recv = bytes.fromhex(msg.split("|")[1])

    ss_hashed = hashlib.sha256(b"VERIFY_SS"+ss).digest()
    expected = hmac.new(ss_hashed, b"VERIFY_SS", hashlib.sha256).digest()
    return hmac.compare_digest(recv, expected)

# Handshake
def rsa_handshake(host1, host2):
    # 1. handshake request & response
    rsa_keyexchange_req(host1, host2.host_id) 
    rsa_keyexchange_rec(host2, host1.host_id)

    # 2. keygen
    rsa_keygen(host1, host2.host_id)

    # 3. encrypt
    ss1 = rsa_encryption(host2, host1.host_id)

    # 4. decrypt
    ss2 = rsa_decryption(host1, host2.host_id)
    
    # 5. Authentication
    print("SS VERIFICATION STEP:")
    send_finished(host1, host2.host_id, ss1)
    matched = verify_finished(host2, host1.host_id, ss2)

    if (matched):
        print("PQC Handshake Successful! Shared secrets match,")
        print("MATCH:", ss1 == ss2)
        print("\n")
    else:
        print("Failure: Shared secrets do not match!")
        return False, None
    
    print("-- STORING SESSION KEY --")
    host1.session_key = ss1
    host2.session_key = ss2
    print(f"Session key stored for {host1.host_id} <-> {host2.host_id}")
    print("\n")
    return True, ss1 # Return both the status and the key

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

    # start ECDH handshake session after request
    print("-- BEGINS RSA HANDSHAKE --")
    start = time.perf_counter()
    auth_result, session_key = rsa_handshake(alice, bob)
    #results['rsa total handshake time'] = time.perf_counter() - start
    print("-- RSA LATENCY --")
    for key in results.keys():
        print(key + " : " + str(results.get(key)))
    print("\n")

    if auth_result:
        print("--- READY FOR QUANTUM OPERATIONS ---")
        # Example: Using the key for a secure entanglement request
        # send_secure_entanglement_request(alice, "Bob", session_key)
    else:
        print("Handshake failed. Aborting.")

    network.draw_classical_network()

if __name__ == '__main__':
    main()