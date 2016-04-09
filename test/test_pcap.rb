#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class PcapHeaderTest < Test::Unit::TestCase
  include PacketFu
  def setup
    @file = File.open('sample.pcap') {|f| f.read}
    @file.force_encoding "binary" if @file.respond_to? :force_encoding
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
    @file.force_encoding "binary" if @file.respond_to? :force_encoding
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

class PcapPacketsTest < Test::Unit::TestCase

  include PacketFu
  def setup
    @file = File.open('sample.pcap') {|f| f.read}
  end

  def test_pcappackets_read
    p = PcapPackets.new
    p.read @file
    assert_equal(11,p.size)
    assert_equal(@file[24,@file.size],p.to_s)
  end

end

class PcapFileTest < Test::Unit::TestCase
  require 'digest/md5'

  include PacketFu
  def setup
    @file = File.open('sample.pcap') {|f| f.read}
    @md5 = '1be3b5082bb135c6f22de8801feb3495'
  end

  def test_pcapfile_read
    p = PcapFile.new
    p.read @file
    assert_equal(3,p.size)
    assert_equal(@file.size, p.sz)
    assert_equal(@file, p.to_s)
  end

  def test_pcapfile_file_to_array
    p = PcapFile.new.file_to_array(:filename => 'sample.pcap')
    assert_equal(@md5.downcase, Digest::MD5.hexdigest(@file).downcase)
    assert_instance_of(Array, p)
    assert_instance_of(String, p[0])
    assert_equal(11,p.size)
    assert_equal(78,p[0].size)
    assert_equal(94,p[1].size)
    assert_equal(74,p[10].size)
  end

  def test_pcapfile_read_and_write
    File.unlink('out.pcap') if File.exists? 'out.pcap'
    p = PcapFile.new
    p.read @file
    p.to_file(:filename => 'out.pcap')
    @newfile = File.open('out.pcap') {|f| f.read(f.stat.size)}
    @newfile.force_encoding "binary" if @newfile.respond_to? :force_encoding
    assert_equal(@file, @newfile)
    p.to_file(:filename => 'out.pcap', :append => true)
    packet_array = PcapFile.new.f2a(:filename => 'out.pcap')
    assert_equal(22, packet_array.size)
  end

  def test_pcapfile_write_after_recalc
    File.unlink('out.pcap') if File.exists? 'out.pcap'
    pcaps = PcapFile.new.file_to_array(:filename => 'sample.pcap')
    pcaps.each {|pkt|
      p = Packet.parse pkt
      p.recalc
      p.to_f('out.pcap','a')
    }
    packet_array = PcapFile.new.f2a(:filename => 'out.pcap')
    assert_equal(11, packet_array.size)
    File.unlink('out.pcap')
  end

  def test_pcapfile_read_and_write_timestamps
    File.unlink('out.pcap') if File.exists? 'out.pcap'
    pf = PcapFile.new
    arr = pf.file_to_array(:filename => 'sample.pcap')
    assert_equal(11, arr.size)
    pf = PcapFile.new
    pf.a2f(:array => arr, :f => 'out.pcap', :ts_inc => 4, 
           :timestamp => Time.now.to_i - 1_000_000)
    diff_time = pf.body[0].timestamp.sec.to_i - pf.body[1].timestamp.sec.to_i
    assert_equal(-4, diff_time)
    File.unlink('out.pcap')
  end

end
  
# Test the legacy Read objects.
class ReadTest < Test::Unit::TestCase

  include PacketFu

  def test_read_string
    pkts = Read.file_to_array(:file => 'sample.pcap')
    assert_kind_of Array, pkts
    assert_equal 11, pkts.size
    this_packet = Packet.parse pkts[0]
    assert_kind_of UDPPacket, this_packet
    that_packet = Packet.parse pkts[3]
    assert_kind_of ICMPPacket, that_packet
  end

  def test_read_hash
    pkts = Read.file_to_array(:file => 'sample.pcap', :ts => true)
    assert_kind_of Array, pkts
    assert_equal 11, pkts.size
    this_packet = Packet.parse pkts[0].values.first
    assert_kind_of UDPPacket, this_packet
    that_packet = Packet.parse pkts[3].values.first
    assert_kind_of ICMPPacket, that_packet
  end

end

class WriteTest < Test::Unit::TestCase

  include PacketFu

  def test_write

  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
