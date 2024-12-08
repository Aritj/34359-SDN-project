#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink


class OpticalBypassTopology:
    def __init__(self, leaf_count, host_count):
        self.net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

        # Add ONOS controller
        self.controller = self.net.addController(
            "c0", controller=RemoteController, ip="127.0.0.1", port=6633
        )

        # Create leaf (ToR) and spine (electrical/optical) switches
        leafs = [self.net.addSwitch("s{}".format(i + 1)) for i in range(leaf_count)]
        e_spine = self.net.addSwitch("s{}".format(leaf_count + 2))
        o_spine = self.net.addSwitch("s{}".format(leaf_count + 3))

        # Configure network topology (leaf-spine fabric)
        for i, leaf in enumerate(leafs):
            # Electrical fabric connections are high latency, low bandwidth.
            self.net.addLink(leaf, e_spine, bw=100, delay="20ms")

            # Optical bypass fabric connections are low latency, high bandwidth.
            self.net.addLink(leaf, o_spine, bw=1000, delay="0.1ms")

            # 4 hosts per leaf
            for j in range(host_count):
                host = self.net.addHost(
                    "h{}{}".format(i, j), ip="10.0.{}.{}".format(i, j + 1)
                )
                self.net.addLink(host, leaf)

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
    setLogLevel("info")
    OpticalBypassTopology(4, 4).start()


if __name__ == "__main__":
    main()
