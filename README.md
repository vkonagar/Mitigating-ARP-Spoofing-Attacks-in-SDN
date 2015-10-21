ARP-Cache-Poisoning-Attack-Mitigator-SDN
========================================
Welcome! I wrote an Application over POX in SDN which can help current SDN enabled networks to mitigate the ARP spoofing attack. This work is copyrighted and is published in ICCTA, Alexandria, Egypt.

## Features
* This will prevent LAN attackers from poisoning the cache tables of the nodes.
* Minimum overhead and detection time.
* Prevent vague packets from entering the network thereby helping current SDN enabled networks to perform more efficiently.

## Setup
* ARPspoofperf.py is used for creating the test topology with the proposed solution.
* ARPspoofperfwithoutsol.py is for creating the test topology without the solution. 

## Video describing the project.
<a href="http://www.youtube.com/watch?feature=player_embedded&v=ls-LIkGDDbc
" target="_blank"><img src="http://img.youtube.com/vi/ls-LIkGDDbc/0.jpg" 
alt="Video" width="240" height="180" border="10" /></a>

## Algorithm:
For algorithm, please refer to the paper.

### How to Run
* Run the POX controller using 
./pox.py log.level --DEBUG proto.dhcpd --network=10.1.1.0/24 --ip=10.1.1.1 forwarding.l2_learning_arp_mitigation
* Run the topology using
sudo mn --mac --controller remote --topo=single,3
