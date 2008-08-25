
require 'examples' # For path setting slight-of-hand
require 'packetfu'

arp_pkt = PacketFu::ARPPacket.new(:flavor => "Windows")
arp_pkt.arp_saddr_mac="00:1c:23:44:55:66"  # Your hardware address
arp_pkt.arp_saddr_ip="10.10.10.17"  # Your IP address
arp_pkt.arp_daddr_ip="10.10.10.1"  # Target IP address
arp_pkt.arp_opcode=1  # Request

puts arp_pkt.to_f('/tmp/arp.pcap').inspect # Write to a file.
