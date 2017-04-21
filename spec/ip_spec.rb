require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/pcap'
require 'tempfile'

include PacketFu

describe IPHeader do
  context "when initializing" do
    before :each do
      @ip_header = IPHeader.new
    end

    it "should have sane defaults" do
      expect(@ip_header.ip_v).to eql(4)
      expect(@ip_header.ip_hl).to eql(5)
      expect(@ip_header.ip_tos).to eql(0)
      expect(@ip_header.ip_len).to eql(20)
      expect(@ip_header.ip_id).to be_kind_of(Integer)
      expect(@ip_header.ip_frag).to eql(0)
      expect(@ip_header.ip_proto).to eql(0)
      expect(@ip_header.ip_sum).to eql(65535)
      expect(@ip_header.ip_src).to eql(0)
      expect(@ip_header.ip_dst).to eql(0)
      expect(@ip_header.ip_src).to be_a(Integer) 
      expect(@ip_header.ip_dst).to be_a(Integer) 
      expect(@ip_header.body).to eql("")
    end

    it "should parse a raw IPHeader" do
      raw_header = "\x45\x10\x00\x4f\x16\xa9\x40\x00\x40\x06\xa2\x9c\xc0\xa8\x00\x02\xc0\xa8\x00\x01"
      @ip_header.read(raw_header)
     
      expect(@ip_header.ip_v).to eql(4)
      expect(@ip_header.ip_hl).to eql(5)
      expect(@ip_header.ip_tos).to eql(16)
      expect(@ip_header.ip_len).to eql(79)
      expect(@ip_header.ip_id).to be_kind_of(Integer)
      expect(@ip_header.ip_frag).to eql(16384)
      expect(@ip_header.ip_proto).to eql(6)
      expect(@ip_header.ip_sum).to eql(41628)
      expect(@ip_header.ip_src).to eql(3232235522)
      expect(@ip_header.ip_dst).to eql(3232235521)
      expect(@ip_header.ip_src).to be_a(Integer) 
      expect(@ip_header.ip_dst).to be_a(Integer) 
      expect(@ip_header.body).to eql("")
    end

  end
end

describe IPPacket do
  context "when initializing" do
    before :each do
      @ip_packet = IPPacket.new
    end

    it "should have sane defaults" do
      expect(@ip_packet.ip_v).to eql(4)
      expect(@ip_packet.ip_hl).to eql(5)
      expect(@ip_packet.ip_tos).to eql(0)
      expect(@ip_packet.ip_len).to eql(20)
      expect(@ip_packet.ip_id).to be_kind_of(Integer)
      expect(@ip_packet.ip_frag).to eql(0)
      expect(@ip_packet.ip_proto).to eql(0)
      expect(@ip_packet.ip_sum).to eql(65535)
      expect(@ip_packet.ip_src).to eql(0)
      expect(@ip_packet.ip_dst).to eql(0)
      expect(@ip_packet.payload).to eql("")
      expect(@ip_packet.is_ip?).to be true
    end

    it "should support peek functionality" do
      @ip_packet.ip_saddr = "1.2.3.4"
      @ip_packet.ip_daddr = "5.6.7.8"
      @ip_packet.ip_proto = 94
      @ip_packet.payload = '\x00' * 30
      @ip_packet.recalc

      expect(@ip_packet.peek).to match(/I\s+154\s+1\.2\.3\.4\s+\->\s+5\.6\.7\.8\s+I:[0-9a-z]{4}/)
    end
  end

  context "when writing a PCAP file to disk" do
    before :each do
      @ip_packet = IPPacket.new
      @temp_file = Tempfile.new('ip_pcap')
    end

    after(:each) { @temp_file.close; @temp_file.unlink }

    it "should write a PCAP file to disk" do
      @ip_packet.ip_saddr = "10.20.30.40"
      @ip_packet.ip_daddr = "50.60.70.80"
      @ip_packet.recalc

      expect(@temp_file.read).to eql("")

      @ip_packet.to_f(@temp_file.path, 'a')
      expect(File.exists?(@temp_file.path))
      expect(@temp_file.read.size).to be >= 49
    end
  end
end
