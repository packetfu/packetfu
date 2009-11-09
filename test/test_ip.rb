#!/usr/bin/env ruby
require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'

class OctetsTest < Test::Unit::TestCase
	include PacketFu

	def test_octets_read
		o = Octets.new
		o.read("\x04\x03\x02\x01")
		assert_equal("4.3.2.1", o.to_x)
	end

	def test_octets_read_quad
		o = Octets.new
		o.read_quad("1.2.3.4")
		assert_equal("1.2.3.4", o.to_x)
		assert_equal("\x01\x02\x03\x04", o.to_s)
		assert_equal(0x01020304, o.to_i)
	end

	def test_ip_header_new
		i = IPHeader.new
		assert_kind_of IPHeader, i
		i.ip_id = 0x1234
		i.ip_recalc :ip_sum
		assert_equal("E\000\000\000\0224\000\000\000\000\250\313\000\000\000\000\000\000\000\000", i.to_s)
	end

	def test_ip_packet_new
		i = IPPacket.new
		assert i.is_ip?
	end

	def test_ip_peek
		i = IPPacket.new
		i.ip_saddr = "1.2.3.4"
		i.ip_daddr = "5.6.7.8"
		i.ip_proto = 94
		i.payload = '\x00' * 30
		i.recalc
		puts "\n"
		puts "IP Peek format: "
		puts i.peek
		assert_equal 78,i.peek.size
	end

	def test_ip_pcap
		i = IPPacket.new
		assert_kind_of IPPacket, i
		i.recalc
		i.to_f('ip_test.pcap')
		i.ip_saddr = "1.2.3.4"
		i.ip_daddr = "5.6.7.8"
		i.ip_proto = 94
		i.payload = "\x23" * 10
		i.recalc
		i.to_f('ip_test.pcap','a')
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
