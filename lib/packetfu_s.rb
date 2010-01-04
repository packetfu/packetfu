$: << File.expand_path(File.dirname(__FILE__))
require "structfu"
require "packetfu/packet_s"
require "packetfu/pcap_s"
require "packetfu/invalid_s"
# This order is desperately important. Should fix this so everyone
# has a chance to require the stuff they need.
require "packetfu/eth_s"
require "packetfu/ip_s" 
require "packetfu/arp_s"
require "packetfu/icmp_s"
require "packetfu/udp_s"
require "packetfu/tcp_s"

module PacketFu
end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
