# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/tcp'
require 'packetfu/protos/udp'
require 'packetfu/protos/icmp'
require 'packetfu/config'
require 'packetfu/pcap'
require 'packetfu/utils'
require 'tempfile'

include PacketFu

describe Inject do
  context "when creating an object from scratch" do
    before :each do
      @inject = PacketFu::Inject.new
    end

    it "should have sane defaults" do
      expect(@inject.array).to be_kind_of(Array)
      expect(@inject.stream).to be_kind_of(Array)
      expect(@inject.iface).to be_kind_of(String)
      expect(@inject.snaplen).to eql(65535)
      expect(@inject.promisc).to eql(false)
      expect(@inject.timeout).to eql(1)
    end

    it "should allow creating an inject object with non-std attributes" do
      # Can only run this if we're root
      if Process.uid == 0
        options = {
          :iface => PacketFu::Utils::default_int,
          :snaplen => 0xfffe,
          :promisc => true,
          :timeout => 5,
        }
        @inject = PacketFu::Capture.new(options)

        expect(@inject.array).to be_kind_of(Array)
        expect(@inject.stream).to be_kind_of(Array)
        expect(@inject.iface).to eql(options[:iface])
        expect(@inject.snaplen).to eql(options[:snaplen])
        expect(@inject.promisc).to eql(options[:promisc])
        expect(@inject.timeout).to eql(options[:timeout])
      end
    end
  end

  context "when injecting on the wire" do
    before :each do
      @inject = PacketFu::Inject.new
    end

    it "should have sane defaults" do
      expect(@inject.array).to be_kind_of(Array)
      expect(@inject.stream).to be_kind_of(Array)
      expect(@inject.iface).to be_kind_of(String)
      expect(@inject.snaplen).to eql(65535)
      expect(@inject.promisc).to eql(false)
      expect(@inject.timeout).to eql(1)
    end

    # Can only run these if we're root
    if Process.uid == 0
      it "should allow creating an inject object with non-std attributes" do
        udp_packet = PacketFu::UDPPacket.new(:iface => PacketFu::Utils::default_int)
        udp_packet.ip_dst = PacketFu::Utils.rand_routable_daddr.to_s
        udp_packet.udp_dport = 12345
        udp_packet.udp_sport = 12345
        udp_packet.payload = "PacketFu test packet"
        udp_packet.recalc
        
        expect(udp_packet.to_w).to eql([1, 1, 62])
      end

      it "should allow creating an inject object with non-std attributes" do
        packet_array = []

        udp_packet = PacketFu::UDPPacket.new(:iface => PacketFu::Utils::default_int)
        udp_packet.ip_dst = PacketFu::Utils.rand_routable_daddr.to_s
        udp_packet.udp_dport = 12345
        udp_packet.udp_sport = 12345
        udp_packet.payload = "PacketFu test packet"
        udp_packet.recalc
        3.times { packet_array << udp_packet.to_s}
        
        inject = PacketFu::Inject.new(:iface => PacketFu::Utils::default_int)
        expect(inject.array_to_wire(:array => packet_array)).to eql([3, 3, 186])
      end
    end
  end 
end