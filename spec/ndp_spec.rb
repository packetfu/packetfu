# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/ndp'
require 'packetfu/pcap'
require 'tempfile'

include PacketFu

describe NDPPacket, "when read from a pcap file" do
  before(:all) do
    parsed_packets = PcapFile.read_packets(File.join(File.dirname(__FILE__),
                                                     "ipv6_ndp.pcap"))
    @ndp_packet = parsed_packets.first
  end

  it "should be recognized as an neighbor discovery packet" do
    expect(@ndp_packet.is_ndp?).to be(true)
  end

  it 'should have the right checksum' do
    expect(@ndp_packet.ndp_sum.to_s(16)).to eq(@ndp_packet.ndp_calc_sum.to_s(16))
  end

  it 'should be recognized as a neighbor advertisement' do
    expect(@ndp_packet.ndp_type).to eq(136)
  end

  it 'should have the right target address' do
    expect(@ndp_packet.ndp_taddr).to eq("2a01:e35:8b7f:9c10:49:aff:fe02:7a21")
  end

  it 'should have the right option type' do
    expect(@ndp_packet.ndp_opt_type).to eq(2)
  end

  it 'should have the right option length' do
    expect(@ndp_packet.ndp_opt_len).to eq(1)
  end

  it 'should have the right link layer address' do
    expect(@ndp_packet.ndp_lladdr).to eq("02:49:0a:02:7a:21")
  end

  context "when initializing NDPHeader from scratch" do
    before :each do
      @ndp_header = NDPHeader.new
    end

    it "should allow setting of type" do
      @ndp_header.ndp_type = 1
      expect(@ndp_header.ndp_type).to eql(1)
    end

    it "should allow setting of target address" do
      @ndp_header.ndp_taddr = "fe80::4"
      expect(@ndp_header.ndp_taddr).to eql("fe80::4")
    end

    it "should allow setting of option type" do
      @ndp_header.ndp_opt_type = 1
      expect(@ndp_header.ndp_opt_type).to eql(1)
    end

    it "should allow setting of option length" do
      @ndp_header.ndp_opt_len = 1
     expect(@ndp_header.ndp_opt_len).to eql(1)
    end

    it "should allow setting of link layer address" do
      @ndp_header.ndp_lladdr = "af:12:01:e1:02:f1"
      expect(@ndp_header.ndp_lladdr).to eql("af:12:01:e1:02:f1")
    end
  end

  context "when initializing NDPPacket from scratch" do
    before :each do
      @ndp_packet = NDPPacket.new
    end

    it "should support peak functionality" do
      @ndp_packet.ipv6_saddr = "::1:1020:3040"
      @ndp_packet.ipv6_daddr = "::1:5060:7080"
      @ndp_packet.ndp_type = 136
      @ndp_packet.recalc
      expect(@ndp_packet.peek).to match(/ND 86\s+::1:1020:3040:pong\s+->\s+::1:5060:7080/)
    end
  end


  context "when reading/writing NDPPacket to disk" do
    before :each do
      @ndp_packet= NDPPacket.new
      @temp_file = Tempfile.new('ndp_pcap')
    end

    after(:each) { @temp_file.close; @temp_file.unlink }

    it "should write a PCAP file to disk" do
      @ndp_packet.ipv6_saddr = "::1:1020:3040"
      @ndp_packet.ipv6_daddr = "::1:5060:7080"
      @ndp_packet.recalc

      expect(@temp_file.read).to eql("")

      @ndp_packet.to_f(@temp_file.path, 'a')
      expect(File.exists?(@temp_file.path))
      expect(@temp_file.read.size).to be >= 79
    end

    it "should read a PCAP file from disk" do
      sample_packet = PcapFile.new.file_to_array(:f => './spec/ipv6_ndp.pcap').first
      pkt = Packet.parse(sample_packet)

      expect(pkt.is_ndp?).to be true
      expect(pkt.class).to eql(PacketFu::NDPPacket)
      expect(pkt.ndp_sum.to_i).to eql(0xb6c3)
      expect(pkt.ndp_type.to_i).to eql(136)
      expect(pkt.ndp_taddr).to eql("2a01:e35:8b7f:9c10:49:aff:fe02:7a21")
      expect(pkt.ndp_opt_type.to_i).to eql(2)
      expect(pkt.ndp_opt_len.to_i).to eql(1)
      expect(pkt.ndp_lladdr).to eql("02:49:0a:02:7a:21")
    end
  end

end
