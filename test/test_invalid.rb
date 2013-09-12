#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class InvalidTest < Test::Unit::TestCase
  include PacketFu

  def test_create_invalid
    p = InvalidPacket.new
    assert_kind_of InvalidPacket, p
    assert_kind_of Packet, p
    assert p.is_invalid?
    assert_equal false, p.is_eth?
    assert_not_equal EthPacket, p.class
  end

  # Sadly, the only way to generate an "InvalidPacket" is
  # to read a packet that's less than 14 bytes. Otherwise,
  # it's presumed to be an EthPacket. TODO: Fix this assumption!
  def test_parse_invalid
    p = Packet.parse("A" * 13)
    assert_kind_of InvalidPacket, p
  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
