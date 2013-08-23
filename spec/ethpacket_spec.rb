$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

include PacketFu

describe EthPacket, "when read from a pcap file" do

  before :all do
    parsed_packets = PcapFile.read_packets(File.join(File.dirname(__FILE__),"sample.pcap"))
    @eth_packet = parsed_packets.first
  end

  context "is a regular ethernet packet" do

    subject { @eth_packet }

    it "should be an EthPacket kind of packet" do
      subject.should be_kind_of EthPacket
    end

    it "should have a dest mac address" do
      subject.eth_daddr.should == "00:03:2f:1a:74:de"
    end

    it "should have a source mac address" do
      subject.eth_saddr.should == "00:1b:11:51:b7:ce"
    end

    its(:size) { should == 78 }

    it "should have a payload in its first header" do
      subject.headers.first.body.should_not be_nil
    end

    context "an EthPacket's first header" do

      subject { @eth_packet.headers.first }

      it "should be 64 bytes" do
        subject.body.sz.should == 64
      end

      context "EthHeader struct members" do
        if RUBY_VERSION =~ /^1\.8/
          its(:members) { should include :eth_dst.to_s }
          its(:members) { should include :eth_src.to_s }
          its(:members) { should include :eth_proto.to_s }
          its(:members) { should include :body.to_s }
        else
          its(:members) { should include :eth_dst }
          its(:members) { should include :eth_src }
          its(:members) { should include :eth_proto }
          its(:members) { should include :body }
        end
      end

    end

  end

  context "isn't a regular Ethernet packet" do

    subject {
      parsed_packets = PcapFile.read_packets(File.join(File.dirname(__FILE__),"vlan-pcapr.cap"))
      parsed_packets.first
    }

    it "should not be an EthPacket" do
      subject.should_not be_kind_of EthPacket
    end

  end

end
