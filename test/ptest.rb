#!/usr/bin/env ruby
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'
include PacketFu


class String
	def bin
		self.scan(/../).map {|x| x.to_i(16).chr}.join
	end
end

@a = TCPPacket.new
@pkt = PcapFile.new.file_to_array(:f => 'sample2.pcap')[3]


