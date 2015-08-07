#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class String
  def bin
    self.scan(/../).map {|x| x.to_i(16).chr}.join
  end
end

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
    assert (u.peek.size <= 80)
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

  def test_udp_read_strip
    str = "01005e7ffffa100ba9eb63400800450000a12d7c0000011159b446a5fb7ceffffffacdf3076c008d516e4d2d534541524348202a20485454502f312e310d0a486f73743a3233392e3235352e3235352e3235303a313930300d0a53543a75726e3a736368656d61732d75706e702d6f72673a6465766963653a496e7465726e6574476174657761794465766963653a310d0a4d616e3a22737364703a646973636f766572220d0a4d583a330d0a0d0a".bin
    str << "0102".bin # Tacking on a couple extra bites tht we'll strip off.
    not_stripped = UDPPacket.new
    not_stripped.read(str)
    assert_equal 135, not_stripped.udp_header.body.length
    stripped = UDPPacket.new
    stripped.read(str, :strip => true)
    assert_equal 133, stripped.udp_header.body.length
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

  def test_udp_reread
    sample_packet = PacketFu::UDPPacket.new
    pkt = Packet.parse(sample_packet.to_s)
    assert sample_packet.is_udp?
    assert pkt.is_udp?
  end


end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
