#!/usr/bin/env ruby
require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu'

class UDPTest < Test::Unit::TestCase
	include PacketFu

	def test_udp_header_new
		u = UDPHeader.new
		assert_kind_of UDPHeader, u
		assert_equal(8, u.to_s.size)
		assert_equal("\x00\x00\x00\x00\x00\x08\x00\x00", u.to_s)
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

	def test_udp_pcap
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

	def test_udp_read
		sample_packet = PcapFile.new.file_to_array(:f => 'sample.pcap')[0]
		pkt = Packet.parse(sample_packet)
		assert_kind_of UDPPacket, pkt
		assert_equal(0x8bf8, pkt.udp_sum.to_i)
		pkt.to_f('udp_test.pcap','a')
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

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
