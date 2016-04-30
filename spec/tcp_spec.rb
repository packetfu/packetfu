require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/tcp'
require 'packetfu/pcap'

include PacketFu

def unusual_numeric_handling_headers(header,i)
  camelized_header = header.to_s.split("_").map {|x| x.capitalize}.join
  header_class = PacketFu.const_get camelized_header
  specify { subject.send(header).should == i }
  specify { subject.send(header).should be_kind_of Integer }
  specify { subject.headers.last[header].should be_kind_of header_class }
end

def tcp_hlen_numeric(i)
  unusual_numeric_handling_headers(:tcp_hlen,i)
end

def tcp_reserved_numeric(i)
  unusual_numeric_handling_headers(:tcp_reserved,i)
end

def tcp_ecn_numeric(i)
  unusual_numeric_handling_headers(:tcp_ecn,i)
end


describe TCPPacket do

  context 'TCPHeader' do
    subject do
      bytes = PcapFile.file_to_array(File.join(File.dirname(__FILE__), "sample2.pcap"))[2]
      packet = Packet.parse(bytes)
    end

    context "TcpHlen reading and setting" do
      context "TcpHlen set via #read" do
        tcp_hlen_numeric(8)
      end
      context "TcpHlen set via an Integer for the setter" do
        (0..15).each do |i|
          context "i is #{i}" do
            before { subject.tcp_hlen = i }
            tcp_hlen_numeric(i)
          end
        end
      end
      context "TcpHlen set via a String for the setter" do
        before { subject.tcp_hlen = "\x60" }
        tcp_hlen_numeric(6)
      end
      context "TcpHlen set via a TcpHlen for the setter" do
        before { subject.tcp_hlen = TcpHlen.new(:hlen => 7) }
        tcp_hlen_numeric(7)
      end
    end

    context "TcpReserved reading and setting" do
      context "TcpReserved set via #read" do
        tcp_reserved_numeric(0)
      end
      context "TcpReserved set via an Integer for the setter" do
        (0..7).each do |i|
          context "i is #{i}" do
            before { subject.tcp_reserved = i }
            tcp_reserved_numeric(i)
          end
        end
      end
      context "TcpReserved set via a String for the setter" do
        before { subject.tcp_reserved = "\x03" }
        tcp_reserved_numeric(3)
      end
      context "TcpReserved set via a TcpReserved for the setter" do
        before { subject.tcp_reserved = TcpReserved.new(:r1 => 1, :r2 => 0, :r3 => 1) }
        tcp_reserved_numeric(5)
      end
    end

    context "TcpEcn reading and setting" do
      context "TcpEcn set via #read" do
        tcp_ecn_numeric(0)
      end
      context "TcpEcn set via an Integer for the setter" do
        (0..7).each do |i|
          context "i is #{i}" do
            before { subject.tcp_ecn = i }
            tcp_ecn_numeric(i)
          end
        end
      end
      context "TcpEcn set via a String for the setter" do
        before { subject.tcp_ecn = "\x00\xc0" }
        tcp_ecn_numeric(3)
      end
      context "TcpEcn set via a TcpEcn for the setter" do
        before { subject.tcp_ecn = TcpEcn.new(:n => 1, :c => 0, :e => 1) }
        tcp_ecn_numeric(5)
      end
    end
  end

  context 'when read from a pcap file' do
    context '(TCP over IPv4)' do
      before(:all) do
        @tcp4_packet = PcapFile.read_packets(File.join(__dir__, '..', 'test',
                                                       'sample2.pcap'))[5]
      end

      it 'should be recognize as a TCP packet' do
        expect(@tcp4_packet).to be_a(TCPPacket)
        expect(@tcp4_packet.is_tcp?).to be(true)
        expect(@tcp4_packet.ipv6?).to be(false)
      end

      it 'should have the right port numbers' do
        expect(@tcp4_packet.tcp_src).to eq(80)
        expect(@tcp4_packet.tcp_dst).to eq(55954)
      end

      it 'should have the right length' do
        expect(@tcp4_packet.tcp_hlen).to eq(8)
      end

      it 'should have the right checksum' do
        expect(@tcp4_packet.tcp_sum).to eq(0x243a)
      end
    end

    context '(TCP over IPv6)' do
      before(:all) do
        @tcp6_packet = PcapFile.read_packets(File.join(__dir__, '..', 'test',
                                                       'sample-ipv6.pcap')).last
      end

      it 'should be recognize as a TCP packet' do
        expect(@tcp6_packet).to be_a(TCPPacket)
        expect(@tcp6_packet.is_tcp?).to be(true)
        expect(@tcp6_packet.ipv6?).to be(true)
      end

      it 'should have the right port numbers' do
        expect(@tcp6_packet.tcp_src).to eq(39278)
        expect(@tcp6_packet.tcp_dst).to eq(443)
      end

      it 'should have the right length' do
        expect(@tcp6_packet.tcp_hlen).to eq(8)
      end

      it 'should have the right checksum' do
        expect(@tcp6_packet.tcp_sum).to eq(0xd8c9)
      end
    end
  end

  context "when initializing TCPPacket from scratch" do
    it "should create TCP on IPv4 packets by default" do
      tcp = TCPPacket.new
      expect(tcp.ip_header).to be_a(IPHeader)
      expect(tcp.ipv6_header).to be_nil
    end

    it "should create TCP on IPv6 packets" do
      tcp = TCPPacket.new(:on_ipv6 => true)
      expect(tcp.ip_header).to be_nil
      expect(tcp.ipv6_header).to be_a(IPv6Header)

      tcp.ipv6_saddr = "::1"
      tcp.ipv6_daddr = "::2"
      tcp.tcp_src = 41000
      tcp.tcp_dst = 42000
      tcp.tcp_seq = 1
      tcp.payload = "\0" * 16
      tcp.recalc
      expect(tcp.tcp_sum).to eq(0x2b98)
      expect(tcp.tcp_hlen).to eq(5)
    end

    it 'should support peek functionnality (IPv4 case)' do
      tcp = TCPPacket.new
      tcp.ip_saddr = '192.168.1.1'
      tcp.ip_daddr = '192.168.1.254'
      tcp.tcp_src = 32756
      tcp.tcp_dst = 80
      tcp.payload = 'abcdefghijklmnopqrstuvwxyz'
      tcp.recalc
      expect(tcp.peek).to match(/T  80\s+192.168.1.1:32756\s+->\s+192.168.1.254:80 \[\.{6,6}\] S:[a-f0-9]+|I:[a-f0-9]+/)
    end

    it 'should support peek functionnality (IPv6 case)' do
      tcp = TCPPacket.new(:on_ipv6 => true)
      tcp.ipv6_saddr = '2000::1'
      tcp.ipv6_daddr = '2001::1'
      tcp.tcp_src = 32756
      tcp.tcp_dst = 80
      tcp.payload = 'abcdefghijklmnopqrstuvwxyz'
      tcp.recalc
      expect(tcp.peek).to match(/6T 100\s+2000::1:32756\s+->\s+2001::1:80 \[\.{6,6}\] S:[a-f0-9]+/)
    end
  end
end
