#!/usr/bin/python

"""
Simple example of setting network and CPU parameters to check ARP spoof mitigation
NOTE: link params limit BW, add latency, and loss.
There is a high chance that pings WILL fail and that
iperf will hang indefinitely if the TCP handshake fails
to complete.
"""

from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
import time

class SingleSwitchTopo(Topo):
	"Single switch connected to n hosts."
	def __init__(self, n=2, **opts):
		Topo.__init__(self, **opts)
		switch1 = self.addSwitch('s1')
		switch2 = self.addSwitch('s2')
		switch3 = self.addSwitch('s3')
		self.addLink(switch1, switch2, bw=100, delay='5ms', loss=0, use_htb=True)
		self.addLink(switch1, switch3, bw=100, delay='5ms', loss=0, use_htb=True)
		# Each host gets 100%/n of system CPU
		host1 = self.addHost('h1', cpu=.5 / n)
		host2 = self.addHost('h2', cpu=.5 / n)
		host3 = self.addHost('h3', cpu=.5 / n)
		host4 = self.addHost('h4', cpu=.5 / n)
		# 10 Mbps, 5ms delay, 10% loss
		self.addLink(host1, switch2, bw=100, delay='5ms', loss=0, use_htb=True)
		self.addLink(host2, switch2, bw=100, delay='5ms', loss=0, use_htb=True)
		self.addLink(host3, switch3, bw=100, delay='5ms', loss=0, use_htb=True)
		self.addLink(host4, switch3, bw=100, delay='5ms', loss=0, use_htb=True)

def perfTest():
    "Create network and run simple performance test"
    topo = SingleSwitchTopo( n=4 )
    net = Mininet( topo=topo, autoSetMacs = True,  
                   host=CPULimitedHost, link=TCLink,
                   autoStaticArp=False, controller=RemoteController )
    print "Dumping host connections"
    net.start()
    dumpNodeConnections(net.hosts)
    CLI(net)
    net.stop()
	
if __name__ == '__main__':
    setLogLevel('info')
    perfTest()
