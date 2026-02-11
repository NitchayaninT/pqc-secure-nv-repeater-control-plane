# Entanglement simple example
# How to add a custom routing function that considers the entanglement in network
''' Network Configuration : 
- A <==> node_1; A <==> node_2
- B <==> node_2; B <==> node_2
'''
from qunetsim.components import Host, Network
from qunetsim.objects import Message, Qubit, Logger
from qunetsim.backends import EQSNBackend
import time
import networkx
import random

network = Network.get_instance() # global

#Logger.DISABLED = True

# create the EQSN backend object
backend = EQSNBackend()

def generate_entanglement(host):
    # Generate entanglement if the host has nothing to process (i.e. is idle)
    while True:
        if host.is_idle():
            host_connections = host.get_connections() # get list of connections for this host
            for connection in host_connections:
                if connection['type'] == 'quantum':
                    num_epr_pairs = len(host.get_epr_pairs(connection['connection'])) # get number of epr pairs established with current host
                    if num_epr_pairs < 4:
                        print("sending epr pairs")
                        print(num_epr_pairs)
                        # send epr pair to the receiver(s) that are connected to the current host
                        # ONLY if the current host hasnt established an epr pair to its connections
                        host.send_epr(connection['connection'], await_ack=True) 
        time.sleep(5)

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

def main():
    # 1. get network instance and insert node_id
    nodes = ['A', 'node_1', 'node_2', 'B']
    network.use_hop_by_hop = False # recalculate the route just once from the beginning
    network.set_delay = 0.2
    network.start(nodes, backend)

    # 2. create host objects and their connections
    A = Host('A', backend)
    A.add_connection('node_1')
    A.add_connection('node_2')
    A.start()

    node_1 = Host('node_1', backend)
    node_1.add_connection('A')
    node_1.add_connection('B')
    node_1.start()

    node_2 = Host('node_2', backend)
    node_2.add_connection('A')
    node_2.add_connection('B')
    node_2.start()

    B = Host('B', backend)
    B.add_connection('node_1')
    B.add_connection('node_2')
    B.start()

    # 3. add hosts to a network
    hosts = [A, node_1, node_2, B]
    for h in hosts:
        network.add_host(h)

    node_1.run_protocol(generate_entanglement)
    node_2.run_protocol(generate_entanglement)

    print('---- BUILDING ENTANGLEMENT   ----')
    # 4. Let the network build up entanglement
    time.sleep(15)
    print('---- DONE BUILDING ENTANGLEMENT   ----')
    # Now, A and B have 2 of the same entanglement pairs
    # so the path A -> node_i -> B is entanglement ready because
    # it’s routing based on entanglement availability on links, not end-to-end A–B entanglement.
    print('---- measuring epr pairs ----')
    A1_pairs = A.get_epr_pairs(host_id=node_1.host_id)
    A2_pairs = A.get_epr_pairs(host_id=node_2.host_id)
    B1_pairs = B.get_epr_pairs(host_id=node_1.host_id)
    B2_pairs = B.get_epr_pairs(host_id=node_2.host_id)
    
    all_pairs = [A1_pairs, A2_pairs, B1_pairs, B2_pairs]
    for pair in all_pairs:
        print(pair)
    
    choices = ['00', '11', '10', '01']
    for i in range(5):
        print('--sending superdense --')
        # 5. send 2 bit binary message via superdense coding to the receiver B
        # superdense coding = sender can transmit 2 classical bits of info to a receiver by sending only one qubit,
        # provided they pre-share an entangled pair of qubits (a Bell pair)
        A.send_superdense(B.host_id, random.choice(choices))
        time.sleep(1)

    # Let the network run for 40 seconds
    time.sleep(40)
    print('stopping')
    network.draw_quantum_network()
    network.stop(stop_hosts=True)

if __name__ == '__main__':
    main()