#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'
puts "Testing #{PacketFu.version}: #{$0}"

class EthTest < Test::Unit::TestCase

  def test_ethmac
    dst = "\x00\x03\x2f\x1a\x74\xde"
    e = PacketFu::EthMac.new
    e.read dst
    assert_equal(dst, e.to_s)
    assert_equal(0x32f, e.oui.oui)
    assert_equal("\x1a\x74\xde", e.nic.to_s)
    assert_equal(222, e.nic.n2)
  end

  def test_ethmac_ipad
    dst = "\x7c\x6d\x62\x01\x02\x03"
    e = PacketFu::EthMac.new
    e.read dst
    assert_equal(dst, e.to_s)
    assert_equal(0x6d62, e.oui.oui)
  end

  def test_ethmac_class
    src = "\x00\x1b\x11\x51\xb7\xce"
    e = PacketFu::EthMac.new
    e.read src
    assert_instance_of(PacketFu::EthMac, e)
  end

  def test_eth
    header = "00032f1a74de001b1151b7ce0800".scan(/../).map { |x| x.to_i(16) }.pack("C*")
    src = "\x00\x1b\x11\x51\xb7\xce"
    dst = "\x00\x03\x2f\x1a\x74\xde"
    e = PacketFu::EthHeader.new
    e.eth_dst = dst
    e.eth_src = src
    e.eth_proto = "\x08\x00"
    assert_equal(header, e.to_s)
    assert_equal(header, PacketFu::EthHeader.new.read(header).to_s)
  end

  def test_macaddr
    dst = "\x00\x03\x2f\x1a\x74\xde"
    dstmac = "00:03:2f:1a:74:de"
    assert_equal(dstmac,PacketFu::EthHeader.str2mac(dst))
    assert_equal(dst, PacketFu::EthHeader.mac2str(dstmac))
  end

end

class EthPacketTest < Test::Unit::TestCase
  include PacketFu

  def test_eth_create
    sample_packet = PcapFile.new.file_to_array(:f => 'sample.pcap')[0]
    e = EthPacket.new
    header = "00032f1a74de001b1151b7ce0800".scan(/../).map { |x| x.to_i(16) }.pack("C*")
    assert_kind_of EthPacket, e
    assert_kind_of EthHeader, e.headers[0]
    assert e.is_eth?
    assert !e.is_tcp?
    e.eth_dst = "\x00\x03\x2f\x1a\x74\xde"
    e.eth_src = "\x00\x1b\x11\x51\xb7\xce"
    e.eth_proto = 0x0800
    assert_equal header, e.to_s[0,14]
  end

  def test_eth_new
    p = EthPacket.new(
    :eth_dst => "\x00\x03\x2f\x1a\x74\xde",
    :eth_src => "\x00\x1b\x11\x51\xb7\xce",
    :eth_proto => 0x0800)
    header = "00032f1a74de001b1151b7ce0800".scan(/../).map { |x| x.to_i(16) }.pack("C*")
    assert_equal header, p.to_s[0,14]
  end

  def test_eth_write
    p = EthPacket.new(
    :eth_dst => "\x00\x03\x2f\x1a\x74\xde",
    :eth_src => "\x00\x1b\x11\x51\xb7\xce",
    :eth_proto => 0x0800)
    p.to_f('eth_test.pcap')
  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
