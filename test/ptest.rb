#!/usr/bin/env ruby
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu'
include PacketFu

class String
	def bin
		self.scan(/../).map {|x| x.to_i(16).chr}.join
	end
end

@p = PcapFile.new
# @p.readfile 'sample.pcap'
@p.file_to_array(:file => "sample.pcap")
@out = []
@out[0] = @p.file_to_array
@out[1] = @p.file_to_array(:ts => true)


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby


