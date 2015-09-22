ARP-Cache-Poisoning-Attack-Mitigator-SDN
========================================
Welcome! I am trying to a make an Application over POX in SDN which can help current SDN enabled networks to perform with more resiliency.

* This will prevent LAN attackers from poisoning the cache tables of the nodes.
* Prevent vague packets from entering the network thereby helping current SDN enabled networks to perform more efficiently.

* ARPspoofperf.py is used for creating the test topology with the proposed solution.

* ARPspoofperfwithoutsol.py is for creating the test topology without the solution. 

<a href="http://www.youtube.com/watch?feature=player_embedded&v=ls-LIkGDDbc
" target="_blank"><img src="http://img.youtube.com/vi/ls-LIkGDDbc/0.jpg" 
alt="Video" width="240" height="180" border="10" /></a>

 ````python
def _handle_PacketIn (self, event):
    packet = event.parsed
    if packet.type == packet.ARP_TYPE:
        if packet.payload.opcode == arp.REQUEST:
            arp_reply = arp()
            arp_reply.hwsrc = <requested mac address>
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = <IP of requested mac-associated machine>
            arp_reply.protodst = packet.payload.protosrc
            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = <requested mac address>
            ether.payload = arp_reply
            #send this packet to the switch
            #see section below on this topic
        elif packet.payload.opcode == arp.REPLY:
            print "It's a reply; do something cool"
        else:
            print "Some other ARP opcode, probably do something smart here"
````



##Algorithm:
````
If FLOW_ENTRY is MATCHED:
	Send it out to the respective egress port for that flow
else:
	Send the packet to the controller

	If OF_PACKET_IN is ARP:
	
		src_mac_a = get_src_MAC_from_ARP()
		src_mac_e = get_src_MAC_from_eth()
		
		if src_mac_a != src_mac_e :
			
			Detected ARP spoofing, Add an entry to the switch to discard the packets matching the SRC ETH MAC, ARP OPCODE
			to drop the packets for some timeout.
			
		else:
			MAC addresses matched
			
			src_ip = get_src_IP_from_ARP()
			
			Check if the src_ip and src_mac_a pair mapping is present at the controller
			
			if src_ip and src_mac_a are NOT valid :
			
				Detected ARP Spoofing, Add an Entry to the switch to discard the packetd matching the SRC ETH MAC, ARP 					OP CODE for some timeout.
			else:
				#VALID
				
				Check if the Dest IP exists in the network.
				
				if dest_IP NOT in network:
					
					Install entry to stop the packets from that host
				else:
					## Allow the packets to flood.
					## INSTALL ENRTY FOR THAT SRC MAC TO FLOOD THE ARP PACKET TO OTHER PORTS
			
	else:
		Compute the route and install the flow entry
````

### How to Run

run the controller using 
./pox.py log.level --DEBUG proto.dhcpd --network=10.1.1.0/24 --ip=10.1.1.1 forwarding.l2_learning_arp_mitigation

run the mininet using
sudo mn --mac --controller remote --topo=single,3
