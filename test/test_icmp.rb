#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class ICMPTest < Test::Unit::TestCase
  include PacketFu

  def test_icmp_header_new
    i = ICMPHeader.new
    assert_kind_of ICMPHeader, i
    assert_equal("\x00\x00\xff\xff", i.to_s)
    i.icmp_type = 1
    i.icmp_recalc :icmp_sum
    assert_equal("\x01\x00\xfe\xff", i.to_s)
  end

  def test_icmp_peek
    i = ICMPPacket.new
    i.ip_saddr = "10.20.30.40"
    i.ip_daddr = "50.60.70.80"
    i.payload = "abcdefghijklmnopqrstuvwxyz"
    i.recalc
    puts "\n"
    puts "ICMP Peek format: "
    puts i.peek
    assert (i.peek.size <= 80)
  end

  def test_icmp_pcap
    i = ICMPPacket.new
    assert_kind_of ICMPPacket, i
    i.recalc
    i.to_f('icmp_test.pcap')
    i.ip_saddr = "10.20.30.40"
    i.ip_daddr = "50.60.70.80"
    i.payload = "\x00\x01\x00\01abcdefghijklmnopqrstuvwxyz"
    i.icmp_code = 8
    i.recalc
    i.to_f('icmp_test.pcap','a')
    assert File.exists?('icmp_test.pcap')
  end

  def test_icmp_read
    sample_packet = PcapFile.new.file_to_array(:f => 'sample.pcap')[2]
    pkt = Packet.parse(sample_packet)
    assert pkt.is_icmp?
    assert_kind_of ICMPPacket, pkt
    assert_equal(0x4d58, pkt.icmp_sum.to_i)
    assert_equal(8, pkt.icmp_type.to_i)
  end

  def test_icmp_reread
    sample_packet = PacketFu::ICMPPacket.new
    pkt = Packet.parse(sample_packet.to_s)
    assert sample_packet.is_icmp?
    assert pkt.is_icmp?
  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
