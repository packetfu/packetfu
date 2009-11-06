#!/usr/bin/env ruby
require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'

class EthPacketTest < Test::Unit::TestCase
	include PacketFu

	def test_parse_eth_packet
		pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
		p = Packet.parse(pcaps[5]) # Really ARP.
		assert_kind_of(Packet,p)
		assert_kind_of(EthHeader, p.headers[0])
		assert p.is_eth?
		assert p.is_ethernet?
		assert_equal(pcaps[5],p.to_s)
	end

	def test_parse_arp_request
		pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
		p = Packet.parse(pcaps[5]) # Really ARP request.
		assert p.is_eth?
		assert_kind_of(ARPPacket,p)
		assert p.is_arp?
		assert_equal(p.to_s, pcaps[5])
		assert_equal(1, p.arp_opcode.to_i)
		assert_equal("\x00\x01", p.arp_opcode.to_s)
	end

	def test_parse_arp_reply
		pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
		p = Packet.parse(pcaps[6]) # Really ARP reply.
		assert_equal(p.to_s, pcaps[6])
		assert_equal(2, p.arp_opcode.to_i)
		assert_equal("\x00\x02", p.arp_opcode.to_s)
	end

end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
