require 'spec_helper'

include PacketFu

describe ICMPPacket, "when read from a pcap file" do

    before :all do
        parsed_packets = PcapFile.read_packets(File.join(File.dirname(__FILE__),"sample.pcap"))
        @icmp_packet = parsed_packets[3]

        parsed_packets3 = PcapFile.read_packets(File.join(File.dirname(__FILE__),"sample3.pcap"))
        @icmp_packet2 = parsed_packets3[8] # contains 0x0A byte in payload
    end

    it "should be recognized as an icmp packet" do
        @icmp_packet.is_icmp?.should be_true
    end

    it "should report the right seq number" do
      @icmp_packet.payload[2..3].unpack("H*")[0].should eq "0003"
    end

    it "should be recognized as an icmp reply packet" do
        @icmp_packet.icmp_type.should eq 0
    end

    it "should have the right checksum" do
      @icmp_packet.icmp_sum.to_s(16).should eq @icmp_packet.icmp_calc_sum.to_s(16)
    end

    it "should have the right checksum even with 0xOA byte in payload" do
      @icmp_packet2.icmp_sum.to_s(16).should eq @icmp_packet2.icmp_calc_sum.to_s(16)
    end

end
