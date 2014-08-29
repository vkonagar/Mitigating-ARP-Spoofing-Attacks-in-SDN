ARP-Cache-Posioning-Attack-Mitigator-SDN
========================================

This is a controller Application on POX which will mitigate ARP cache poisoning attacks in SDN networks.
'''
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
'''
