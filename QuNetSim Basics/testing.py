from qunetsim.components import Host, Network
from qunetsim.objects import Message, Qubit, Logger
from qunetsim.backends import EQSNBackend
Logger.DISABLED = True

# create the EQSN backend object
backend = EQSNBackend()


def protocol_1(host, receiver):
    # Here we write the protocol code for a host.
    for i in range(5):
        s = 'Hi {}.'.format(receiver)
        print("{} sends: {}".format(host.host_id, s))
        host.send_classical(receiver, s, await_ack=True)
    for i in range(5):
        q = Qubit(host)
        q.X()
        print("{} sends qubit in the |1> state".format(host.host_id))
        host.send_qubit(receiver, q, await_ack=True)


def protocol_2(host, sender):
    # Here we write the protocol code for another host.
    for i in range(5):
        sender_message = host.get_classical(sender, wait=5, seq_num=i)
        print("{} Received classical: {}".format(host.host_id, sender_message.content))
    for i in range(5):
        q = host.get_qubit(sender, wait=10)
        m = q.measure()
        print("{} measured: {}".format(host.host_id, m))


def main():
    network = Network.get_instance()
    nodes = ['A', 'B', 'C', 'D']
    network.generate_topology(nodes, 'mesh')
    network.start(nodes)

    host_a = network.get_host('A')
    host_b = network.get_host('B')
    host_c = network.get_host('C')
    host_d = network.get_host('D')

    t1 = host_a.run_protocol(protocol_1, (host_d.host_id,))
    t2 = host_d.run_protocol(protocol_2, (host_a.host_id,), blocking=True)
    network.stop(True)


if __name__ == '__main__':
    main()
