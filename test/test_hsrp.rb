#!/usr/bin/env ruby
require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu'

class HSRPTest < Test::Unit::TestCase
	include PacketFu

	def test_hsrp_read
		sample_packet = PcapFile.new.file_to_array(:f => 'sample_hsrp_pcapr.cap')[0]
		pkt = Packet.parse(sample_packet)
		assert pkt.is_hsrp?
		assert pkt.is_udp?
		assert_equal(0x2d8d, pkt.udp_sum.to_i)
		# pkt.to_f('udp_test.pcap','a')
	end

=begin
# The rest of these tests are snarfed from UDP. TODO: need to update
# these for hsrp, shouldn't be long.
	def test_hsrp_pcap
		u = UDPPacket.new
		assert_kind_of UDPPacket, u
		u.recalc
		u.to_f('udp_test.pcap','a')
		u.ip_saddr = "10.20.30.40"
		u.ip_daddr = "50.60.70.80"
		u.payload = "+some fakey-fake udp packet"
		u.udp_src = 1205
		u.udp_dst = 13013
		u.recalc
		u.to_f('udp_test.pcap','a')
	end

	def test_udp_peek
		u = UDPPacket.new
		u.ip_saddr = "10.20.30.40"
		u.ip_daddr = "50.60.70.80"
		u.udp_src = 53
		u.udp_dport = 1305
		u.payload = "abcdefghijklmnopqrstuvwxyz"
		u.recalc
		puts "\n"
		puts "UDP Peek format: "
		puts u.peek
		assert_equal 78,u.peek.size
	end

	def test_udp_checksum
		sample_packet = PcapFile.new.file_to_array(:f => 'sample.pcap')[0]
		pkt = Packet.parse(sample_packet)
		assert_kind_of UDPPacket, pkt
		pkt.recalc
		assert_equal(0x8bf8, pkt.udp_sum.to_i)
		pkt.to_f('udp_test.pcap','a')
	end

	def test_udp_alter
		sample_packet = PcapFile.new.file_to_array(:f => 'sample.pcap')[0]
		pkt = Packet.parse(sample_packet)
		assert_kind_of UDPPacket, pkt
		pkt.payload = pkt.payload.gsub(/metasploit/,"MeatPistol")
		pkt.recalc
		assert_equal(0x8341, pkt.udp_sum)
		pkt.to_f('udp_test.pcap','a')
	end
=end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
