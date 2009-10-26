#!/usr/bin/env ruby

require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'

class PcapHeaderTest < Test::Unit::TestCase
  include PacketFu
  def setup
    @file = File.open('sample.pcap') {|f| f.read}
    @file_magic = @file[0,4]
    @file_header = @file[0,24]
  end

  def test_header_size
    assert_equal(24, PcapHeader.new.sz)
    assert_equal(24, PcapHeader.new.sz)
  end

  # If this fails, the rest is pretty much for naught.
  def test_read_file
    assert_equal("\xd4\xc3\xb2\xa1", @file_magic) # yep, it's libpcap.
  end

  def test_endian_magic
    p = PcapHeader.new # usual case
    assert_equal(@file_magic, p.to_s[0,4]) 
    p = PcapHeader.new(:endian => :big)
    assert_equal("\xa1\xb2\xc3\xd4", p.to_s[0,4])
  end

  def test_header
    p = PcapHeader.new
    assert_equal(@file_header, p.to_s[0,24])
    p = PcapHeader.new(:endian => :big)
    assert_not_equal(@file_header, p.to_s[0,24])
    # We want to ensure our endianness is little or big.
    assert_raise(ArgumentError) {PcapHeader.new(:endian => :just_right)}
  end

  def test_header_read
    p = PcapHeader.new
    p.read @file
    assert_equal(@file_header,p.to_s)
  end

end

class TimestampTest < Test::Unit::TestCase
  include PacketFu
  def setup
    @file = File.open('sample.pcap') {|f| f.read}
    @ts = @file[24,8]
  end

  def test_timestamp_size
    assert_equal(3, Timestamp.new.size) # Number of elements
    assert_equal(8, Timestamp.new.sz) # Length of the string (in PacketFu)
  end

  def test_timestamp_read
    t = Timestamp.new
    t.read(@ts)
    assert_equal(@ts, t.to_s)
  end
end

class PcapPacketTest < Test::Unit::TestCase
  include PacketFu
  def setup
    @file = File.open('sample.pcap') {|f| f.read}
    @header = @file[0,24]
    @packet = @file[24,100] # pkt is 78 bytes + 16 bytes pcap hdr == 94
  end

  def test_pcappacket_read
    p = PcapPacket.new :endian => :little
    p.read(@packet)
    assert_equal(78,@packet[8,4].unpack("V").first)
    assert_equal(@packet[8,4].unpack("V").first,p[:incl_len].to_i)
    assert_equal(@packet[0,94],p.to_s)
  end

end
