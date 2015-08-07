require 'spec_helper'

include PacketFu


describe UDPPacket do

  context "new" do

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
