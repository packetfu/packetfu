# -*- coding: binary -*-

require './examples' # For path setting slight-of-hand
require 'packetfu'

eth_pkt = PacketFu::EthPacket.new
eth_pkt.eth_saddr="01:02:03:04:05:06"
eth_pkt.eth_daddr="0a:0b:0c:0d:0e:0f"
eth_pkt.payload="I'm a lonely little eth packet with no real protocol information to speak of."
puts eth_pkt.to_f('/tmp/e.pcap').inspect

