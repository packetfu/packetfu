#!/usr/bin/ruby

# Functional test script contributed by @dmaciejak
# Still need a real test set.
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

def lldp_pcap
  fname = "./sample_lldp.pcap"
  fname if File.readable? fname
end

def lldp_test()
  raise RuntimeError, "Need a sample_lldp.pcap to check!" unless lldp_pcap
  cap = PacketFu::PcapFile.new.file_to_array(:filename => lldp_pcap)
  cap.each do |p|
        pkt = PacketFu::Packet.parse p
        if pkt.is_lldp?
          packet_info = [pkt.proto.last, pkt.lldp_capabilty, pkt.lldp_address_type_readable, pkt.lldp_address, pkt.lldp_interface_type, pkt.lldp_interface]
          puts "%s | %15s | %15s | %15s | %15s | %15s |" % packet_info
        end
  end
end

lldp_test()
