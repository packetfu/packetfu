#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class IPv6AddrTest < Test::Unit::TestCase
  include PacketFu

  def test_addr_read
    a = AddrIpv6.new
    addr = "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x1a\xc5\xff\xfe\x00\x01\x52"
    a.read(addr)
    assert_equal(338288524927261089654170548082086773074, a.to_i)
    assert_equal("fe80::21a:c5ff:fe00:152",a.to_x)
  end

  def test_octets_read_quad
    a = AddrIpv6.new
    addr = "fe80::21a:c5ff:fe00:152"
    a.read_x(addr)
    assert_equal(addr,a.to_x)
  end

end

class IPv6Test < Test::Unit::TestCase
  include PacketFu

  def test_ipv6_header_new
    i = IPv6Header.new
    assert_kind_of IPv6Header, i
    assert_equal("`\000\000\000\000\000\000\377\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000", i.to_s)
  end

  def test_ipv6_packet_new
    i = IPv6Packet.new
    assert i.is_ipv6?
  end

  def test_ipv6_peek
    i = IPv6Packet.new
    i.ipv6_saddr = "fe80::1"
    i.ipv6_daddr = "fe80::2"
    i.ipv6_next = 0x11
    i.payload = '\x00' * 30
    i.recalc
    puts "\n"
    puts "IPv6 Peek format: "
    puts i.peek
    assert (i.peek.size <= 80)
  end

=begin
  def test_ipv6_pcap
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
=end
end
# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
