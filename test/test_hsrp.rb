#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class HSRPTest < Test::Unit::TestCase
  include PacketFu

  def test_hsrp_read
    sample_packet = PcapFile.new.file_to_array(:f => 'sample_hsrp_pcapr.cap')[0]
    pkt = Packet.parse(sample_packet)
    assert pkt.is_hsrp?
    assert pkt.is_udp?
    assert_equal(0x2d8d, pkt.udp_sum.to_i)
    # pkt.to_f('udp_test.pcap','a')
  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
