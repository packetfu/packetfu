require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/udp'
require 'packetfu/pcap'

include PacketFu

describe UDPPacket do

  context 'when read from a pcap file' do
    context '(UDP over IPv4)' do
      before(:all) do
        @udp4_packet = PcapFile.read_packets(File.join(File.dirname(__FILE__),
                                                       "ipv4_udp.pcap")).first
      end

      it 'should be recognized as a UDP packet' do
        expect(@udp4_packet.is_udp?).to be(true)
      end

      it 'should have the right port numbers' do
        expect(@udp4_packet.udp_src).to eq(41000)
        expect(@udp4_packet.udp_dst).to eq(42000)
      end

      it 'should have the right length' do
        expect(@udp4_packet.udp_len).to eq(24)
      end

      it 'should have the right checksum' do
        expect(@udp4_packet.udp_sum).to eq(0xbd81)
      end
    end

    context '(UDP over IPv6)' do
      before(:all) do
        @udp6_packet = PcapFile.read_packets(File.join(File.dirname(__FILE__),
                                                       "ipv6_udp.pcap")).first
      end

      it 'should be recognized as a UDP packet' do
        expect(@udp6_packet.is_udp?).to be(true)
      end

      it 'should have the right port numbers' do
        expect(@udp6_packet.udp_src).to eq(6809)
        expect(@udp6_packet.udp_dst).to eq(6810)
      end

      it 'should have the right length' do
        expect(@udp6_packet.udp_len).to eq(12)
      end

      it 'should have the right checksum' do
        expect(@udp6_packet.udp_sum).to eq(0xb9be)
      end
    end
  end

  context "when initializing UDPPacket from scratch" do
    it "should create UDP on IPv4 packets by default" do
      udp = UDPPacket.new
      expect(udp.ip_header).to be_a(IPHeader)
      expect(udp.ipv6_header).to be_nil
    end

    it "should create UDP on IPv6 packets" do
      udp = UDPPacket.new(:on_ipv6 => true)
      expect(udp.ip_header).to be_nil
      expect(udp.ipv6_header).to be_a(IPv6Header)

      udp.ipv6_saddr = "::1"
      udp.ipv6_daddr = "::2"
      udp.udp_src = 41000
      udp.udp_dst = 42000
      udp.payload = "\0" * 16
      udp.recalc
      expect(udp.udp_sum).to eq(0xbb82)
      expect(udp.udp_len).to eq(24)
    end
  end
end
