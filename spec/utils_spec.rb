# -*- coding: binary -*-

require 'spec_helper'

include PacketFu

describe Utils do
  context "when using ifconfig" do
    it "should prevent non-interface values" do
      expect {
        PacketFu::Utils.ifconfig("not_an_interface")
      }.to raise_error(ArgumentError, /interface does not exist$/)
    end

    it "should work on Mac OSX Yosemite" do
      mac_osx_reply = "ifconfig en0\n" + 
                      "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n" +
                      "ether 78:31:c1:ce:39:bc\n" +
                      "inet6 fe80::7a31:c1ff:fece:39bc%en0 prefixlen 64 scopeid 0x4\n" +
                      "inet 192.168.10.173 netmask 0xffffff00 broadcast 192.168.10.255\n" +
                      "nd6 options=1<PERFORMNUD>\n" +
                      "media: autoselect\n" +
                      "status: active\n"
      allow(PacketFu::Utils).to receive(:ifconfig_data_string) { mac_osx_reply }
      util_reply = PacketFu::Utils.ifconfig

      # Ensure we got a hash back
      expect(util_reply).to be_a(::Hash)

      # Ensure all our values parse correctly
      expect(util_reply[:iface]).to eq("ifconfig en0")
      expect(util_reply[:eth_saddr]).to eq("78:31:c1:ce:39:bc")
      expect(util_reply[:eth_src]).to eq("x1\xC1\xCE9\xBC")
      expect(util_reply[:ip6_saddr]).to eq("fe80::7a31:c1ff:fece:39bc")
      expect(util_reply[:ip6_obj]).to eq(IPAddr.new("fe80::7a31:c1ff:fece:39bc"))
      expect(util_reply[:ip_saddr]).to eq("192.168.10.173")
      expect(util_reply[:ip_src]).to eq("\xC0\xA8\n\xAD")
      expect(util_reply[:ip4_obj]).to eq(IPAddr.new("192.168.10.0/24"))
    end
  end
end