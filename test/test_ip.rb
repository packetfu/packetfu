#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class IPTest < Test::Unit::TestCase
  include PacketFu

  def test_ip_header_new
    i = IPHeader.new
    assert_kind_of IPHeader, i
    i.ip_id = 0x1234
    i.ip_recalc :ip_sum
    assert_equal("E\000\000\024\0224\000\000 \000\210\267\000\000\000\000\000\000\000\000", i.to_s)
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
    assert (i.peek.size <= 80)
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
