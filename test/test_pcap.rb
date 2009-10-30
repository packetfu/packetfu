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
		p = PcapFile.new.read @file
		p.to_file(:filename => 'out.pcap')
		@newfile = File.open('out.pcap') {|f| f.read}
		assert_equal(@file, @newfile)
		p.to_file(:filename => 'out.pcap', :append => true)
		packet_array = PcapFile.new.f2a(:filename => 'out.pcap')
		assert_equal(22, packet_array.size)
	end

	def test_pcapfile_write_again
		p = PcapFile.new.read @file
		p.write('out.pcap')
		@newfile = File.open('out.pcap') {|f| f.read}
		assert_equal(@file, @newfile)
		p.append('out.pcap')
		packet_array = PcapFile.new.f2a(:filename => 'out.pcap')
		assert_equal(22, packet_array.size)
		File.unlink('out.pcap')
	end

	def test_pcapfile_write_yet_again
		p = PcapFile.new.read @file
		p.write(:filename => 'out.pcap')
		@newfile = File.open('out.pcap') {|f| f.read}
		assert_equal(@file, @newfile)
		p.append(:filename => 'out.pcap')
		packet_array = PcapFile.new.f2a(:filename => 'out.pcap')
		assert_equal(22, packet_array.size)
		File.unlink('out.pcap')
	end

	def test_pcapfile_write_default
		p = PcapFile.new.read @file
		p.write
		@newfile = File.open('out.pcap') {|f| f.read}
		assert_equal(@file, @newfile)
		p.append
		packet_array = PcapFile.new.f2a(:filename => 'out.pcap')
		assert_equal(22, packet_array.size)
		File.unlink('out.pcap')
	end

end
