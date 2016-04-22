# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

module PacketFu
  module PcapNG
    describe File do
      before(:all) do
        @file = ::File.join(__dir__, '../..', 'test', 'sample.pcapng')
        @file_spb = ::File.join(__dir__, '../..', 'test', 'sample-spb.pcapng')
      end
      before(:each) { @pcapng = File.new }

      context '#read' do
        it 'reads a Pcap-NG file' do
          @pcapng.read @file
          expect(@pcapng.sections.size).to eq(1)

          expect(@pcapng.sections.first.interfaces.size).to eq(1)
          intf = @pcapng.sections.first.interfaces.first
          expect(intf.section).to eq(@pcapng.sections.first)

          expect(intf.packets.size).to eq(11)
          packet = intf.packets.first
          expect(packet.interface).to eq(intf)
        end

        it 'reads a Pcap-NG file with Simple Packet blocks' do
          @pcapng.read @file_spb
          expect(@pcapng.sections.size).to eq(1)
          expect(@pcapng.sections.first.interfaces.size).to eq(1)
          intf = @pcapng.sections.first.interfaces.first
          expect(intf.section).to eq(@pcapng.sections.first)
          expect(intf.packets.size).to eq(4)
          expect(intf.snaplen.to_i).to eq(0)
          packet = intf.packets.first
          expect(packet.interface).to eq(intf)
          expect(packet.data.size).to eq(packet.orig_len.to_i)
        end

        it 'yields xPB object per read packet' do
          idx = 0
          @pcapng.read(@file) do |pkt|
            expect(pkt).to be_a(@Pcapng::EPB)
            idx += 1
          end
          expect(idx).to eq(11)
        end
      end

      context '#read_packets' do
        before(:all) do
          @expected = [UDPPacket] * 2 + [ICMPPacket] * 3 + [ARPPacket] * 2 +
            [TCPPacket] * 3 + [ICMPPacket]
        end

        it 'returns an array of Packets' do
          packets = @pcapng.read_packets(@file)
          expect(packets.map(&:class)).to eq(@expected)

          icmp = packets[2]
          expect(icmp.ip_saddr).to eq('192.168.1.105')
          expect(icmp.ip_daddr).to eq('216.75.1.230')
          expect(icmp.icmp_type).to eq(8)
          expect(icmp.icmp_code).to eq(0)
        end

        it 'yields Packet object per read packet' do
          idx = 0
          @pcapng.read_packets(@file) do |pkt|
            expect(pkt).to be_a(@expected[idx])
            idx += 1
          end
          expect(idx).to eq(11)
        end
      end

      it '#to_s returns object as a String' do
        orig_str = PacketFu.force_binary(::File.read(@file))
        @pcapng.read @file
        expect(@pcapng.to_s).to eq(orig_str)

        @pcapng.clear
        orig_str = PacketFu.force_binary(::File.read(@file_spb))
        @pcapng.read @file_spb
        expect(@pcapng.to_s).to eq(orig_str)
      end
    end
  end
end
