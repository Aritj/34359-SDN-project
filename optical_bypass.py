#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

class OpticalBypassTopo:
    def __init__(self):
        self.net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

        # Add ONOS controller
        self.controller = self.net.addController(
            'c0',
            controller=RemoteController,
            ip='127.0.0.1',
            port=6633,
        )

        # Create leaf switches (TOR)
        leafs = [self.net.addSwitch('tor_{}'.format(i)) for i in range(4)]

        # Create spine switches
        e_spine = self.net.addSwitch('s5')
        o_spine = self.net.addSwitch('s6')

        # Add hosts
        for i, leaf in enumerate(leafs):
            for j in range(1,5): # 4 per TOR
                host = self.net.addHost('h{}{}'.format(i, j), ip='10.0.0.{}'.format(i*10+j))
                self.net.addLink(host, leaf)

        # Electrical fabric connections are high latency, low bandwidth.
        e_bw = 40  # electrical bandwidth
        e_delay = "20ms"  # electrical delay

        # Optical bypass fabric connections are low latency, high bandwidth.
        o_bw = 100  # optical bandwidth
        o_delay = "0.1ms"  # optical delay

        # Link each leaf switch to both spine switches
        for leaf in leafs:
            self.net.addLink(leaf, e_spine, bw=e_bw, delay=e_delay)
            self.net.addLink(leaf, o_spine, bw=o_bw, delay=o_delay)

    def start(self):
        self.net.build()
        self.controller.start()
        for switch in self.net.switches:
            switch.start([self.controller])
        self.net.start()
        CLI(self.net)

    def stop(self):
        self.net.stop()

def main():
    setLogLevel('info')
    topo = OpticalBypassTopo()
    topo.start()

if __name__ == '__main__':
    main()
