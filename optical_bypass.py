#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def main(leaf_switch_count = 4, hosts_per_leaf_count = 4):
    # Set logging level
    setLogLevel('info')

    # Create the network
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

    # Add ONOS controller
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    # Define leaf-spine fabric connection parameters
    electrical_params = {'bw': 10, 'delay': "100ms"} # High latency, low bandwidth
    optical_params = {'bw': 1000, 'delay': "0.01ms"} # Low latency, high bandwidth
    host_params = {} # Undefined

    # Create spine switches
    e_spine = net.addSwitch('s{}'.format(leaf_switch_count+1), protocols='OpenFlow13')
    o_spine = net.addSwitch('s{}'.format(leaf_switch_count+2), protocols='OpenFlow13')

    # Create leaf switches and links to both spine switches
    for leaf_index in range(1, leaf_switch_count + 1):
        leaf = net.addSwitch('s{}'.format(leaf_index), protocols='OpenFlow13')

        # Add hosts before spines, so that they connect to ports corresponding to host index
        for host_index in range(1, hosts_per_leaf_count + 1):
            host_name = 'h{}{}'.format(leaf_index, host_index)
            host_ip = '10.0.{}.{}'.format(leaf_index, host_index)
            host = net.addHost(host_name, ip=host_ip)

            net.addLink(host, leaf, **host_params)

        net.addLink(leaf, e_spine, **electrical_params)
        net.addLink(leaf, o_spine, **optical_params)


    # Start the network
    net.build()
    controller.start()
    for switch in net.switches:
        switch.start([controller])
    net.start()

    # Open the CLI
    CLI(net)

    # Stop the network
    net.stop()

if __name__ == '__main__':
    main()
