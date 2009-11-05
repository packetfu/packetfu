#!/usr/bin/env ruby
require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'

class ArpTest < Test::Unit::TestCase
	include PacketFu

	def setup
		@pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
	end

	def test_create_header
		a = ARPHeader.new
		assert_kind_of ARPHeader, a 
		assert_kind_of StructFu::Int16, a.arp_hw
		assert_kind_of Octets, a.arp_src_ip
		assert_kind_of EthMac, a.arp_dst_mac
		assert_kind_of StructFu::String, a.body 
	end
	
	def test_create_packet
		a = ARPPacket.new
		assert_kind_of ARPPacket, a
		assert_kind_of StructFu::Int16, a.arp_hw
		assert_kind_of Octets, a.arp_src_ip
		assert_kind_of EthMac, a.arp_dst_mac
		assert_kind_of String, a.payload 
	end

	def test_read_header
		real_arp = @pcaps[5][14,28]
		a = ARPHeader.new
		a.read(real_arp)
		assert_equal(real_arp, a.to_s)
		assert_equal("192.168.1.105", a.arp_saddr_ip)
		assert_equal("192.168.1.2", a.arp_daddr_ip)
		assert_equal("00:00:00:00:00:00", a.arp_daddr_mac)
		assert_equal("00:1b:11:51:b7:ce", a.arp_saddr_mac)
	end

	def test_read_packet
		real_arp = @pcaps[5]
		a = ARPPacket.new
		a.read(real_arp)
		assert_equal(real_arp, a.to_s)
	end

	def test_write_ip
		a = ARPPacket.new
		a.arp_saddr_ip="1.2.3.4"
		a.arp_daddr_ip="5.6.7.8"
		assert_equal("5.6.7.8",a.arp_daddr_ip)
		assert_equal("1.2.3.4",a.arp_saddr_ip)
		assert_equal("\x01\x02\x03\x04",a.arp_src_ip.to_s)
		assert_equal("\x05\x06\x07\x08",a.arp_dst_ip.to_s)
	end

	def test_write_mac
		a = ARPPacket.new
		a.arp_saddr_mac = "00:01:02:03:04:05"
		a.arp_daddr_mac = "00:06:07:08:09:0a"
		assert_equal("00:01:02:03:04:05",a.arp_saddr_mac)
		assert_equal("00:06:07:08:09:0a",a.arp_daddr_mac)
		assert_equal("\x00\x01\x02\x03\x04\x05",a.arp_src_mac.to_s)
		assert_equal("\x00\x06\x07\x08\x09\x0a",a.arp_dst_mac.to_s)
	end

	def test_arp_flavors_windows
		a = ARPPacket.new(:flavor => "Windows")
		assert_equal("\x00" * 64, a.payload.to_s)
		a = ARPPacket.new(:flavor => "Linux")
		assert_equal(32, a.payload.size)
		a = ARPPacket.new(:flavor => :hp_deskjet)
		assert_equal(18, a.payload.size)
		a = ARPPacket.new
		assert_equal("\x00" * 18, a.payload.to_s)
	end

end

class ArpCreateTest < Test::Unit::TestCase
	include PacketFu

	def setup
		@pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
	end

	def test_create_packet
		ref = @pcaps[6]
		arp = ARPPacket.new
		assert_kind_of ARPPacket, arp
		arp.arp_hw = 1
		arp.arp_proto = 0x0800
		arp.arp_hw_len = 6
		arp.arp_proto_len = 4 
		arp.arp_opcode = 2
		arp.arp_src_mac = "\x00\x03\x2f\x1a\x74\xde"
		arp.arp_src_ip = "\xc0\xa8\x01\x02"
		arp.arp_dst_mac = "\x00\x1b\x11\x51\xb7\xce"
		arp.arp_dst_ip = "\xc0\xa8\x01\x69"
		arp.payload = "\xc0\xa8\x01\x69"
		assert_equal(ref[14,0xffff],arp.to_s[14,0xffff])
	end
	
	def test_new
		ref = @pcaps[6]
		arp = ARPPacket.new(:arp_hw => 1, :arp_proto => 0x0800,
											 :arp_opcode => 2, :arp_src_ip => "\xc0\xa8\x01\x02")
		assert_kind_of ARPPacket, arp
		arp.arp_hw_len = 6
		arp.arp_proto_len = 4 
		arp.arp_src_mac = "\x00\x03\x2f\x1a\x74\xde"
		arp.arp_dst_mac = "\x00\x1b\x11\x51\xb7\xce"
		arp.arp_dst_ip = "\xc0\xa8\x01\x69"
		arp.payload = "\xc0\xa8\x01\x69"
		assert_equal(ref[14,0xffff],arp.to_s[14,0xffff])
	end
	
end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
