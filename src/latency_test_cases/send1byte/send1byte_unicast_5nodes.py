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
import networkx
import hmac

kem_name = "ML-KEM-768" # for kyber 768
sign_algo = "ML-DSA-44" 

# payload list
PQC_SYN = "PQC_SYN"
PQC_ACK = "PQC_ACK"
PQC_READY = "PQC_READY"
PQC_SEND_PK = "PQC_SEND_PK"
PQC_SEND_CT = "PQC_SEND_CT"
PQC_DONE = "PQC_DONE"

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

    network.quantum_routing_algo = routing_algorithm

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
        host.send_classical(receiver_id, "B") # in qunetsim, they can only carry string msgs
        # time taken of Pk transmission
        result_name = 'pk_transmission ' + host.host_id + '<->' + receiver_id
        results[result_name] = time.perf_counter() - alice_received_pk_start
        return None

    # FOR CT -> BYTE = 1
    def pqc_encaps(host, receiver_id):
        msg = host.get_classical(receiver_id, wait=5)[0].content
        while msg.startswith("PQC_SYN"):
            print("Alice's pk hasnt arrived to Eva yet, waiting...")
            msg= host.get_classical(receiver_id, wait=5)[0].content
        print("Received msg : ", msg)
        print("Byte count : ", len(msg))

        # get bob's signed pk, sk is in global
        # Signs handshake transcript (all previous messages) with the private signature key
        transcript = msg + 'A' # ct is also 1 byte in this model
        transcript_hash = hashlib.sha256(transcript.encode()).digest()

        if(host.host_id == "Bob"):
            with oqs.Signature(sign_algo, secret_key=bob_sk) as signer:
                sig_B = signer.sign(transcript_hash) # signature of the transcript using the signature key as the key, which proves that the sender owns the shared secret and is not an imposter
            print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
            alice_received_ct_start = time.perf_counter()
            host.send_classical(receiver_id,'A' + "|" + sig_B.hex() + "|" + bob_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (bob's signature key) together
        elif(host.host_id == "Cathy"):
            with oqs.Signature(sign_algo, secret_key=cathy_sk) as signer:
                sig_C = signer.sign(transcript_hash)    
            print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
            alice_received_ct_start = time.perf_counter()
            host.send_classical(receiver_id,'A' + "|" + sig_C.hex() + "|" + cathy_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (cathy's signature key) together
            
        elif(host.host_id == "Dave"):
            with oqs.Signature(sign_algo, secret_key=dave_sk) as signer:
                sig_D = signer.sign(transcript_hash)
            print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
            alice_received_ct_start = time.perf_counter()
            host.send_classical(receiver_id,'A' + "|" + sig_D.hex() + "|" + dave_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (dave's signature key) together
        
        elif(host.host_id == "Eva"):
            with oqs.Signature(sign_algo, secret_key=eva_sk) as signer:
                sig_E = signer.sign(transcript_hash)
            print(host.host_id, PQC_SEND_CT, " -> ", receiver_id)
            alice_received_ct_start = time.perf_counter()
            host.send_classical(receiver_id,'A' + "|" + sig_E.hex() + "|" + eva_pk.hex()) # sends ciphertext, signature key (CertificateVerify) and Certificate (eva's signature key) together
        
        #start = time.perf_counter() # start encaps
        result_name = 'ct_transmission ' + host.host_id + '<->' + receiver_id
        results[result_name] = time.perf_counter() - alice_received_ct_start
        return None

    # PQC decapsulation 
    def pqc_decaps(host, receiver_id, kem_host):
        ct_msg = host.get_classical(receiver_id, wait=5)[0].content
        ct, sig_hex, receiver_pk_hex = ct_msg.split("|")
        sig = bytes.fromhex(sig_hex)
        receiver_pk = bytes.fromhex(receiver_pk_hex)
        print("Byte count : ", len(ct_msg))

        # Verify the signature using the receiver's public key to authenticate that the message is indeed from the expected sender and has not been tampered with
        transcript = 'B' + ct # record of the messages being sent
        transcript_hash = hashlib.sha256(transcript.encode()).digest()

        with oqs.Signature(sign_algo) as verifier:
            if verifier.verify(transcript_hash, sig, receiver_pk):
                print("Signature verification successful! Message is authenticated and has not been tampered with.")
            else:
                print("Signature verification failed! Message may have been tampered with or is not from the expected sender.")
                return None 
                
        return None

    def pqc_handshake(host1, host2):
        # initiate PQC key exchange request/response
        pqc_keyexchange_req(host1, host2.host_id) 
        pqc_keyexchange_rec(host2, host1.host_id)

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
            pqc_keygen(host1, host2.host_id) 
            pqc_encaps(host2, host1.host_id)
            pqc_decaps(host1, host2.host_id, None)
            '''for i in range (node_count-1):
                next_node = route[i+1]
                print("Starting handshake between ", route[i], " and ", next_node)
                
                current_node = network.get_host(route[i])
                peer = network.get_host(next_node)
            
                # 1) host2 sgenerates a public, private key pair and sends public key to host1
                #t_keygen_start = time.time()
                pqc_keygen(current_node, next_node) # gets host2's sk
            
                # 2) host1 encapsulates and sends ciphertext -> host2 gets ciphertext
                #t_encap_start = time.time()
                pqc_encaps(peer, current_node.host_id) # uses host2's pk to encapsulate a shared secret and sends ct to host2
            
                # 3) host2 decapsulates -> get shared secret
                #t_decap_start = time.time()
                pqc_decaps(current_node, next_node, None) # uses host2's kem object
                #t_decap_end = time.time()
            '''
        return None


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
    print("pk transmission time: ", results['pk_transmission Alice<->Eva'] )
    print("ct transmission time: ", results['ct_transmission Eva<->Alice'] )

    return results['pk_transmission Alice<->Eva'], results['ct_transmission Eva<->Alice'],t1-t0 


if __name__ == '__main__':
     for trial in range(1, NUM_TRIALS + 1):
        pk_latency, ct_latency, overall_latency = run_one_trial()

        with open("1byte_pk_latency.txt", "a") as f:
            f.write(f"{trial},{pk_latency}\n")

        with open("1byte_ct_latency.txt", "a") as f:
            f.write(f"{trial},{ct_latency}\n")

        with open("1byte_overall_latency.txt", "a") as f:
            f.write(f"{trial},{overall_latency}\n")

        print(f"Trial {trial} done")