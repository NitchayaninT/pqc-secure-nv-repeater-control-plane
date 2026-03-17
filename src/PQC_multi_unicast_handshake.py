# Path-based Parallel Handshake Establishment for Long-Distance Entanglement
# This example : 5 nodes
# 1. Entanglement request for Repeater A, E
# 2. Compute shortest path for A and E
# 3. Parallel PQC Handshake along the path (A-B-C-D-E)
    # Repeater A sends its pk to B, B replicates A's pk and send to C, C sends A'spk to D, D sends A's pk to E (in parallel)
# 4. Repeater A then waits for ciphertexts from all nodes
# 5. Authentication with all nodes along the path
# This is important before all nodes in the shortest path can be trusted before doing entanglement swapping 

from qunetsim.components import Host
from qunetsim.components import Network
from qunetsim.objects import Logger
from qunetsim.objects import Message
from qunetsim.objects import Qubit
from qunetsim.backends import EQSNBackend
import time
import networkx
import oqs
import hashlib
import hmac 
import threading

kem_name = "ML-KEM-768" # for kyber 768
sign_algo = "ML-DSA-44" 

network = Network.get_instance()
backend = EQSNBackend()
results = {} 
handshake_state = {}  
# structure: handshake_state["Alice"]["Bob"] = {"kem": ..., "ss_enc": ..., "ss_dec": ...}

# payload list
PQC_SYN = "PQC_SYN"
PQC_ACK = "PQC_ACK"
PQC_READY = "PQC_READY"
PQC_SEND_PK = "PQC_SEND_PK"
PQC_SEND_CT = "PQC_SEND_CT"
PQC_DONE = "PQC_DONE"

NUM_TRIALS = 100

def run_one_trial():
    def handshake_with_node(alice, node_id, bucket):
        bucket[node_id] = {}
        bucket[node_id]["kem"], bucket[node_id]["pk_hex"] = pqc_keygen(alice, node_id)

        peer = network.get_host(node_id)
        bucket[node_id]["ss_enc"] = pqc_encaps(peer, alice.host_id)

        bucket[node_id]["ss_dec"] = pqc_decaps(alice, node_id, bucket[node_id]["kem"], bucket[node_id]["pk_hex"])

        send_finished(alice, node_id, bucket[node_id]["ss_dec"])
        auth_ok = verify_finished(peer, alice.host_id, bucket[node_id]["ss_enc"])
        bucket[node_id]["auth_ok"] = auth_ok

        print("-- AUTHENTICATION RESULT --")
        print(bucket[node_id]["auth_ok"])

    def routing_algorithm(di_graph, source, dest):
        """
        Chosen algorithm : Dijkstra's
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
        # -- WILL EDIT THIS --
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

    def pqc_keyexchange_req(host, receiver_id, payload=PQC_SYN):
        # Request PQC key exchange
        print(host.host_id, " PQC_SYN -> ", receiver_id)
        # wait forever until ack received
        host.send_classical(receiver_id, payload)
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

        # Alice sends her public key to Bob, and Bob receives it
        print(host.host_id, PQC_SEND_PK, " -> ", receiver_id)
        bob_received_pk_start = time.perf_counter()
        host.send_classical(receiver_id, pk.hex()) # in qunetsim, they can only carry string msgs
        
        # time taken of Pk transmission
        results_name = 'pk_transmission ' + host.host_id + '<->' + receiver_id
        results[results_name] = time.perf_counter() - bob_received_pk_start
        print("PQC_SEND_PK_ACK received")
        return kem_receiver, pk.hex()

    # PQC encapsulation
    def pqc_encaps(host, receiver_id):
        pk_msg = host.get_classical(receiver_id, wait=5)[0].content
        if(host.host_id == "Eva"):
            while(pk_msg.startswith("PQC_SYN")):
                print("Alice's pk hasnt arrived to Eva yet. Waiting for pk...")
                pk_msg = host.get_classical(receiver_id, wait=5)[0].content
        # pk hasnt arrived yet for Eva
        pk_bytes = bytes.fromhex(pk_msg) # because we sent hex string
        print("Byte count = ",len(pk_bytes))

        #start = time.perf_counter() # start encaps
        with oqs.KeyEncapsulation(kem_name) as kem:
            ct, ss_enc = kem.encap_secret(pk_bytes) # only accept a byte type object
            
            # calculate encaps computation time
            #results['encap_cpu'] = time.perf_counter() - start
            
            # get bob's signed pk, sk is in global
            # Signs handshake transcript (all previous messages) with the private signature key
            transcript = pk_bytes + ct # in a real implementation, this would include all previous handshake messages, but for simplicity we just use pk and ct
            transcript_hash = hashlib.sha256(transcript).digest()

            if(host.host_id == "Bob"):
                with oqs.Signature(sign_algo, secret_key=bob_sk) as signer:
                    sig_B = signer.sign(transcript_hash) # signature of the transcript using the signature key as the key, which proves that the sender owns the shared secret and is not an imposter
                    # sends ct and signature back to alice
                print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
                alice_received_ct_start = time.perf_counter()
                host.send_classical(receiver_id,ct.hex() + "|" + sig_B.hex() + "|" + bob_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (bob's signature key) together
            elif(host.host_id == "Cathy"):
                with oqs.Signature(sign_algo, secret_key=cathy_sk) as signer:
                    sig_C = signer.sign(transcript_hash)    
                print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
                alice_received_ct_start = time.perf_counter()
                host.send_classical(receiver_id,ct.hex() + "|" + sig_C.hex() + "|" + cathy_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (cathy's signature key) together
                
            elif(host.host_id == "Dave"):
                with oqs.Signature(sign_algo, secret_key=dave_sk) as signer:
                    sig_D = signer.sign(transcript_hash)
                print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
                alice_received_ct_start = time.perf_counter()
                host.send_classical(receiver_id,ct.hex() + "|" + sig_D.hex() + "|" + dave_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (dave's signature key) together
            
            elif(host.host_id == "Eva"):
                with oqs.Signature(sign_algo, secret_key=eva_sk) as signer:
                    sig_E = signer.sign(transcript_hash)
                print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
                alice_received_ct_start = time.perf_counter()
                host.send_classical(receiver_id,ct.hex() + "|" + sig_E.hex() + "|" + eva_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (eva's signature key) together
            
            results_name = 'ct_transmission ' + host.host_id + '<->' + receiver_id
            results[results_name] = time.perf_counter() - alice_received_ct_start
            print("PQC_CT_ACK received")
        return ss_enc # alice gets their shared secret from bob's pk

    # PQC decapsulation
    # alice has to receive Ct from all nodes
    def pqc_decaps(host, receiver_id, kem_host, pk_hex):
        ct_msg = host.get_classical(receiver_id, wait=5)[0].content 
        ct_hex, sig_hex, receiver_pk_hex = ct_msg.split("|")
        ct_bytes = bytes.fromhex(ct_hex)
        sig = bytes.fromhex(sig_hex) # get signature
        receiver_pk_bytes = bytes.fromhex(receiver_pk_hex) # uses the receiver's signature public key to verify signature
        print("Byte count ct = ",len(ct_bytes))
        print("Byte count sig = ",len(sig))
        print("Byte count receiver_pk = ",len(receiver_pk_bytes))

        # Verify the signature using the receiver's public key to authenticate that the message is indeed from the expected sender and has not been tampered with
        transcript = bytes.fromhex(pk_hex) + ct_bytes # record of the messages being sent
        transcript_hash = hashlib.sha256(transcript).digest()

        with oqs.Signature(sign_algo) as verifier:
            if verifier.verify(transcript_hash, sig, receiver_pk_bytes):
                print("Signature verification successful! Message is authenticated and has not been tampered with.")
            else:
                print("Signature verification failed! Message may have been tampered with or is not from the expected sender.")
                return None 

        start = time.perf_counter()
        with oqs.KeyEncapsulation(kem_name) as kem:
            # uses bob's internal private key to decap the received ciphertext
            ss_dec = kem_host.decap_secret(ct_bytes)

            # calculates decap computation time
            results['decap_cpu'] = time.perf_counter() - start
            print(PQC_DONE)
        return ss_dec

    # after handshake, Alice can send a message to Bob with HMAC 
    def send_finished(host, receiver_id, ss):
        ss_hashed = hashlib.sha256(b"VERIFY_SS" + ss).digest()
        finished = hmac.new(ss_hashed, b"VERIFY_SS", hashlib.sha256).digest()
        host.send_classical(receiver_id, "FIN|" + finished.hex(),await_ack=True)

    # then Bob can verify whether the shared secret is the same by comparing the received HMAC with the expected HMAC using the shared secret he has
    def verify_finished(host, peer_id, ss) -> bool:
        msg = host.get_classical(peer_id, wait=5)[0].content
        if not msg.startswith("FIN|"):
            print("Unexpected message format. Expected FIN message.")
            return False
        recv = bytes.fromhex(msg.split("|")[1])

        print("Byte count HMAC+FIN = ",len(recv))
        ss_hashed = hashlib.sha256(b"VERIFY_SS"+ss).digest()
        expected = hmac.new(ss_hashed, b"VERIFY_SS", hashlib.sha256).digest()
        return hmac.compare_digest(recv, expected)

    # This is different from 2 node version, but first, it checks if the node is adjacent
    def pqc_handshake(host1, host2):
        pqc_keyexchange_req(host1, host2.host_id) 
        pqc_keyexchange_rec(host2, host1.host_id)

        bucket = hs_bucket(host1.host_id) # bucket for alice to store the kem objects and shared secrets for each node in the path
        
        host1.get_connections() 
        connections = host1.get_connections()
        adjacent = False
        for c in connections:
            if c['connection'] == host2.host_id:
                adjacent = True
                break

        if not adjacent:
            print("Hosts are not adjacent. Please establish handshake in middle node first before doing PQC handshake.")
            route = network.get_quantum_route(host1.host_id, host2.host_id) # get shortest path
            print("Route for handshake: ", route)
            
            # do handshake between alice and every node PARALLELLY
            threads=[]
            for node_id in route[1:]:
                print("Starting handshake thread for node: ", node_id)
                t = threading.Thread(target=handshake_with_node, args=(host1, node_id, bucket))
                t.start()
                threads.append(t)

        for t in threads: t.join()
        return True, None # indicate successful handshake


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
    # for multinode, try doing handshake for every single link since we want to see how long it takes for all nodes to finish the handshake
    print("-- BEGINS PQC HANDSHAKE FOR EVERY NODE--")
    t0 = time.perf_counter()
    auth_result_ae, session_key_ae = pqc_handshake(alice, eva) # 4 hops, alice - eva. but need to do handshake for the middle nodes as well, by sending alice's pk to everyone
    t1 = time.perf_counter()

    print("-- PQC LATENCY --")
    for key in results.keys():
        print(key + " : " + str(results.get(key)))
    print("PQC Overall Handshake Time: ", t1 - t0)
    print("\n")
    if auth_result_ae:
        print("--- READY FOR QUANTUM OPERATIONS ---")
        # Example: Using the key for a secure entanglement request
        # send_secure_entanglement_request(alice, "Bob", session_key)
    else:
        print("Handshake failed. Aborting.")

    sum_pk = results['pk_transmission Alice<->Bob'] + results['pk_transmission Alice<->Cathy'] + results['pk_transmission Alice<->Dave'] + results['pk_transmission Alice<->Eva']

    sum_ct = results['ct_transmission Bob<->Alice'] + results['ct_transmission Cathy<->Alice'] + results['ct_transmission Dave<->Alice'] + results['ct_transmission Eva<->Alice']

    print("total pk transmission time: ", sum_pk)
    print("total ct transmission time: ", sum_ct)
    return sum_pk, sum_ct, t1-t0
        #network.draw_classical_network()

if __name__ == '__main__':
    for trial in range(1, NUM_TRIALS + 1):
        pk_latency, ct_latency, overall_latency = run_one_trial()

        with open("pqc_multiuni_pk_latency.txt", "a") as f:
            f.write(f"{trial},{pk_latency}\n")

        with open("pqc_multiuni_ct_latency.txt", "a") as f:
            f.write(f"{trial},{ct_latency}\n")

        with open("pqc_multiuni_overall_latency.txt", "a") as f:
            f.write(f"{trial},{overall_latency}\n")

        print(f"Trial {trial} done")