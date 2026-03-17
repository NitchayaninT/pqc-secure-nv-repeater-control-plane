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
import networkx
import os, oqs
import hashlib
import hmac

sign_algo = "ML-DSA-44" 

# payload list
RSA_SYN = "RSA_SYN"
RSA_ACK = "RSA_ACK"
RSA_READY = "RSA_READY"
RSA_SEND_PK = "RSA_SEND_PK"
RSA_SEND_CT = "RSA_SEND_CT"
RSA_DONE = "RSA_DONE"

NUM_TRIALS = 100 

network = Network.get_instance()
backend = EQSNBackend()
results = {} # to keep results of each process' latency
handshake_state = {}  

def run_one_trial():
    def routing_algorithm(di_graph, source, dest):
        """
        Entanglement based routing function. Note: any custom routing function must
        have exactly these three parameters and must return a list ordered by the steps
        in the route.

        Args:
            di_graph (networkx DiGraph): The directed graph representation of the network.
            source (str): The sender ID
            target (str: The receiver ID
        Returns:
            (list): The route ordered by the steps in the route.
        """

        # Build a graph with the vertices, hosts, edges, connections
        entanglement_network = networkx.DiGraph()
        nodes = di_graph.nodes() # nodes within the graph representation
        # Generate entanglement network
        for node in nodes:
            host = network.get_host(node)
            host_connections = host.get_connections()
            for connection in host_connections:
                if connection['type'] == 'quantum':
                    num_epr_pairs = len(host.get_epr_pairs(connection['connection']))
                    if num_epr_pairs == 0:
                    # when there is no entanglement, add a large weight to that edge
                        entanglement_network.add_edge(host.host_id, connection['connection'], weight=1000)
                    else :
                        # the weight of each edge is the inverse of the amount of entanglement shared on that link
                        entanglement_network.add_edge(host.host_id, connection['connection'], weight=1. / num_epr_pairs)

        try:
            # Compute the shortest path on this newly generated graph
            # from sender to receiver and return the route
            route = networkx.shortest_path(entanglement_network, source, dest, weight='weight')
            print('-------' + str(route) + '-------')
            return route
        except Exception as e:
            Logger.get_instance().error(e)

    def dijsktra_routing(di_graph, source, dest):
        # Build a graph with the vertices, hosts, edges, connections
        entanglement_network = networkx.DiGraph()
        nodes = di_graph.nodes() # nodes within the graph representation
        # Generate entanglement network
        for node in nodes:
            host = network.get_host(node)
            host_connections = host.get_connections()
            for connection in host_connections:
                if connection['type'] == 'quantum':
                    entanglement_network.add_edge(host.host_id, connection['connection'], weight=1)

        try:
            # Compute the shortest path on this newly generated graph
            # from sender to receiver and return the route
            route = networkx.shortest_path(entanglement_network, source, dest, weight='weight')
            print('-------' + str(route) + '-------')
            return route
        except Exception as e:
            Logger.get_instance().error(e)

    network.quantum_routing_algo = dijsktra_routing

    # get/create STATE bucket from each node
    def hs_bucket(host_id: str):
        if host_id not in handshake_state:
            handshake_state[host_id] = {}
        return handshake_state[host_id]

    def generate_long_term_sig_keys():
        with oqs.Signature(sign_algo) as sig:
            pub = sig.generate_keypair()
            sk = sig.export_secret_key()
        return pub, sk

    # generate long term "signature keys" for Bob, Cathy, Dave, Eva 
    # to sign the handshake messages so that Alice can verify the authenticity of the messages she receives from the repeaters during the handshake
    bob_pk, bob_sk = generate_long_term_sig_keys()
    cathy_pk, cathy_sk = generate_long_term_sig_keys()
    dave_pk, dave_sk = generate_long_term_sig_keys()
    eva_pk, eva_sk = generate_long_term_sig_keys()

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
        pk_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,  
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
        
        alice_received_pk_start = time.perf_counter()
        host.send_classical(receiver_id, pk_bytes.hex())
        result_name = 'pk_transmission ' + host.host_id + '<->' + receiver_id
        results[result_name] = time.perf_counter() - alice_received_pk_start
        
        return public_key

    # Encryption
    # encrypts a random secret key with receiver's pk
    def rsa_encryption(host, receiver_id):
        public_key = host.get_classical(receiver_id, wait=5)[0].content
        while public_key.startswith("RSA_SYN"):
            print("Alice's pk hasnt arrived to Eva yet, waiting...")
            public_key = host.get_classical(receiver_id, wait=5)[0].content
        pk_bytes = bytes.fromhex(public_key) 
        public_key = serialization.load_der_public_key(pk_bytes)
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
        transcript = public_key.public_bytes(encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo) + encapsulated_key # in a real implementation, this would include all previous handshake messages, but for simplicity we just use pk and ct
        transcript_hash = hashlib.sha256(transcript).digest()

        if(host.host_id == "Bob"):
            with oqs.Signature(sign_algo, secret_key=bob_sk) as signer:
                sig_B = signer.sign(transcript_hash) # signature of the transcript using the signature key as the key, which proves that the sender owns the shared secret and is not an imposter
                    # sends ct and signature back to alice
            print(host.host_id, RSA_SEND_CT, " -> ", receiver_id)
            alice_received_ct_start = time.perf_counter()
            host.send_classical(receiver_id,encapsulated_key.hex() + "|" + sig_B.hex() + "|" + bob_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (bob's signature key) together
        elif(host.host_id == "Cathy"):
            with oqs.Signature(sign_algo, secret_key=cathy_sk) as signer:
                sig_C = signer.sign(transcript_hash)    
            print(host.host_id, RSA_SEND_CT, " -> ", receiver_id)
            alice_received_ct_start = time.perf_counter()
            host.send_classical(receiver_id,encapsulated_key.hex() + "|" + sig_C.hex() + "|" + cathy_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (cathy's signature key) together
            
        elif(host.host_id == "Dave"):
            with oqs.Signature(sign_algo, secret_key=dave_sk) as signer:
                sig_D = signer.sign(transcript_hash)
            print(host.host_id, RSA_SEND_CT, " -> ", receiver_id)
            alice_received_ct_start = time.perf_counter()
            host.send_classical(receiver_id,encapsulated_key.hex() + "|" + sig_D.hex() + "|" + dave_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (dave's signature key) together
        
        elif(host.host_id == "Eva"):
            with oqs.Signature(sign_algo, secret_key=eva_sk) as signer:
                sig_E = signer.sign(transcript_hash)
            print(host.host_id, RSA_SEND_CT, " -> ", receiver_id)
            alice_received_ct_start = time.perf_counter()
            host.send_classical(receiver_id,encapsulated_key.hex() + "|" + sig_E.hex() + "|" + eva_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (eva's signature key) together

        # Send encrypted msg to receiver
        #host.send_classical(receiver_id, encapsulated_key.hex(), await_ack=True)
        result_name = 'ct_transmission ' + host.host_id + '<->' + receiver_id
        results[result_name] = time.perf_counter() - alice_received_ct_start
        return ss1

    # Decryption
    def rsa_decryption(host, receiver_id, pk):
        ct = host.get_classical(receiver_id, wait=5)[0].content
        ct_hex, sig_hex, receiver_pk_hex = ct.split("|")

        ct_bytes = bytes.fromhex(ct_hex)
        sig = bytes.fromhex(sig_hex)
        cert_pk = bytes.fromhex(receiver_pk_hex)  
        #receiver_pk_bytes = bytes.fromhex(receiver_pk_hex)
        print("Ct byte count : ",len(ct_bytes))

        # Verify the signature using the receiver's public key to authenticate that the message is indeed from the expected sender and has not been tampered with
        transcript = pk.public_bytes( encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo) + ct_bytes # record of the messages being sent
        transcript_hash = hashlib.sha256(transcript).digest()

        with oqs.Signature(sign_algo) as verifier:
            if verifier.verify(transcript_hash, sig, cert_pk):
                print("Signature verification successful! Message is authenticated and has not been tampered with.")
            else:
                print("Signature verification failed! Message may have been tampered with or is not from the expected sender.")
                return None 
            
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

    # Handshake
    def rsa_handshake(host1, host2):
        # 1. handshake request & response
        rsa_keyexchange_req(host1, host2.host_id) 
        rsa_keyexchange_rec(host2, host1.host_id)

        host1.get_connections() 
        connections = host1.get_connections()
        adjacent = False
        for c in connections:
            if c['connection'] == host2.host_id:
                adjacent = True
                break

        if not adjacent:  
            print("Hosts are not adjacent. Please establish handshake in middle node first before doing PQC handshake.")
            route = network.get_quantum_route(host1.host_id, host2.host_id)
            print("Route for handshake: ", route)  

            node_count = len(route)
            pk_sender = rsa_keygen(host1, host2.host_id)
            ss1 = rsa_encryption(host2, host1.host_id) 
            ss2 = rsa_decryption(host1, host2.host_id, pk_sender)

            # authentication
            send_finished(host1, host2.host_id, ss2)
            auth_ok = verify_finished(host2, host1.host_id, ss1)

            if not auth_ok:
                print("Authentication failed with ", host2.host_id)
                return False, None
            print("Authentication successful with ", host2.host_id)
            
            '''for i in range(node_count-1):
                next_node = route[i+1]
                print("Starting handshake between ", route[i], " and ", next_node)
                current_node = network.get_host(route[i])
                peer = network.get_host(next_node)
            
                # 2. keygen
                pk_sender = rsa_keygen(current_node, next_node)

                # 3. encrypt
                ss1 = rsa_encryption(peer, current_node.host_id)

                # 4. decrypt
                ss2 = rsa_decryption(current_node, peer.host_id, pk_sender)
                

                # 5. Authentication
                send_finished(current_node, next_node, ss2)
                auth_ok = verify_finished(peer, current_node.host_id, ss1)
                
                if not auth_ok:
                    print("Authentication failed with ", next_node)
                    return False, None
                print("Authentication successful with ", next_node)
            '''
            return True, None


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

    print("pk transmission time: ", results['pk_transmission Alice<->Eva'] )
    print("ct transmission time: ", results['ct_transmission Eva<->Alice'] )

    return results['pk_transmission Alice<->Eva'], results['ct_transmission Eva<->Alice'], results['rsa total handshake time'] 


if __name__ == '__main__':
    for trial in range(1, NUM_TRIALS + 1):
        pk_latency, ct_latency, overall_latency = run_one_trial()

        with open("rsa_pk_latency.txt", "a") as f:
            f.write(f"{trial},{pk_latency}\n")

        with open("rsa_ct_latency.txt", "a") as f:
            f.write(f"{trial},{ct_latency}\n")

        with open("rsa_overall_latency.txt", "a") as f:
            f.write(f"{trial},{overall_latency}\n")

        print(f"Trial {trial} done")