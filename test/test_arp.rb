#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'
class ArpTest < Test::Unit::TestCase
  include PacketFu

  def test_arp_header
    a = ARPHeader.new
    assert_kind_of ARPHeader, a 
    assert_kind_of StructFu::Int16, a[:arp_hw]
    assert_kind_of Fixnum, a.arp_hw
    assert_kind_of Octets, a[:arp_src_ip]
    assert_kind_of String, a.arp_src_ip
    assert_kind_of EthMac, a[:arp_dst_mac]
    assert_kind_of String, a.arp_dst_mac
    assert_kind_of StructFu::String, a.body 
  end

  def test_read_header
    a = ARPHeader.new
    sample_arp = "000108000604000200032f1a74dec0a80102001b1151b7cec0a80169"
    sample_arp = sample_arp.scan(/../).map {|x| x.to_i(16)}.pack("C*")
    a.read(sample_arp)
    assert_equal(sample_arp, a.to_s)
    assert_equal("192.168.1.105", a.arp_daddr_ip)
    assert_equal("192.168.1.2", a.arp_saddr_ip)
    assert_equal("00:1b:11:51:b7:ce", a.arp_daddr_mac)
    assert_equal("00:03:2f:1a:74:de", a.arp_saddr_mac)
  end

  def test_arp_read
    a = ARPPacket.new
    sample_arp = "001b1151b7ce00032f1a74de0806000108000604000200032f1a74dec0a80102001b1151b7cec0a80169c0a80169"
    sample_arp = sample_arp.scan(/../).map {|x| x.to_i(16)}.pack("C*")
    a.read(sample_arp)
    assert_equal(sample_arp, a.to_s)
  end

  def test_write_ip
    a = ARPPacket.new
    a.arp_saddr_ip="1.2.3.4"
    a.arp_daddr_ip="5.6.7.8"
    assert_equal("1.2.3.4",a.arp_saddr_ip)
    assert_equal("5.6.7.8",a.arp_daddr_ip)
    assert_equal("\x01\x02\x03\x04",a.arp_src_ip)
    assert_equal("\x05\x06\x07\x08",a.arp_dst_ip)
  end

  def test_write_mac
    a = ARPPacket.new
    a.arp_saddr_mac = "00:01:02:03:04:05"
    a.arp_daddr_mac = "00:06:07:08:09:0a"
    assert_equal("00:01:02:03:04:05",a.arp_saddr_mac)
    assert_equal("00:06:07:08:09:0a",a.arp_daddr_mac)
    assert_equal("\x00\x01\x02\x03\x04\x05",a.arp_src_mac)
    assert_equal("\x00\x06\x07\x08\x09\x0a",a.arp_dst_mac)
  end

  def test_arp_flavors
    a = ARPPacket.new(:flavor => "Windows")
    assert_equal("\x00" * 64, a.payload)
    a = ARPPacket.new(:flavor => "Linux")
    assert_equal(32, a.payload.size)
    a = ARPPacket.new(:flavor => :hp_deskjet)
    assert_equal(18, a.payload.size)
    a = ARPPacket.new
    assert_equal("\x00" * 18, a.payload)
  end

  def test_arp_create
    sample_arp = "000108000604000200032f1a74dec0a80102001b1151b7cec0a80169"
    sample_arp = sample_arp.scan(/../).map {|x| x.to_i(16)}.pack("C*")
    a = ARPPacket.new
    assert_kind_of ARPPacket, a
    a.arp_hw = 1
    a.arp_proto = 0x0800
    a.arp_hw_len = 6
    a.arp_proto_len = 4 
    a.arp_opcode = 2
    a.arp_src_mac = "\x00\x03\x2f\x1a\x74\xde"
    a.arp_src_ip = "\xc0\xa8\x01\x02"
    a.arp_dst_mac = "\x00\x1b\x11\x51\xb7\xce"
    a.arp_dst_ip = "\xc0\xa8\x01\x69"
    a.payload = ""
    assert_equal(sample_arp,a.to_s[14,0xffff])
  end

  def test_arp_new
    sample_arp = "000108000604000200032f1a74dec0a80102001b1151b7cec0a80169c0a80169"
    sample_arp = sample_arp.scan(/../).map {|x| x.to_i(16)}.pack("C*")
    arp = ARPPacket.new(:arp_hw => 1, :arp_proto => 0x0800,
                       :arp_opcode => 2, :arp_src_ip => "\xc0\xa8\x01\x02")
    assert_kind_of ARPPacket, arp
    arp.arp_hw_len = 6
    arp.arp_proto_len = 4 
    arp.arp_src_mac = "\x00\x03\x2f\x1a\x74\xde"
    arp.arp_dst_mac = "\x00\x1b\x11\x51\xb7\xce"
    arp.arp_dst_ip = "\xc0\xa8\x01\x69"
    arp.payload = "\xc0\xa8\x01\x69"
    assert_equal(sample_arp,arp.to_s[14,0xffff])
  end

  def test_arp_peek
    a = ARPPacket.new
    puts "\n"
    puts "ARP Peek format: "
    puts a.peek
    puts "\n"
    assert(a.peek.size <= 80)
  end

  def test_arp_pcap
    a = ARPPacket.new
    assert_kind_of ARPPacket, a
    a.to_f('arp_test.pcap','w')
    a.arp_hw = 1
    a.arp_proto = 0x0800
    a.arp_hw_len = 6
    a.arp_proto_len = 4 
    a.arp_opcode = 2
    a.arp_src_mac = "\x00\x03\x2f\x1a\x74\xde"
    a.arp_src_ip = "\xc0\xa8\x01\x02"
    a.arp_dst_mac = "\x00\x1b\x11\x51\xb7\xce"
    a.arp_dst_ip = "\xc0\xa8\x01\x69"
    a.payload = ""
    a.eth_daddr = "00:1b:11:51:b7:ce"
    a.eth_saddr = "00:03:2f:1a:74:de"
    a.to_f('arp_test.pcap','a')
  end
  
end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
