#!/usr/bin/env ruby
$:.unshift File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu'
include PacketFu

class String
	def bin
		self.scan(/../).map {|x| x.to_i(16).chr}.join
	end
end

@t = TCPPacket.new

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby


