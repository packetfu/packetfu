#!/usr/bin/env ruby
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'
include PacketFu

class String
	def bin
		self.scan(/../).map {|x| x.to_i(16).chr}.join
	end
end
File.unlink('out.pcap') if File.exists? 'out.pcap'
puts "Reading pcaps...."
start = Time.now
pcaps = PcapFile.new.file_to_array(:filename => '/tmp/in.pcap')
puts "#{pcaps.size} packets read."
stop = Time.now
puts "#{stop - start} seconds elapsed."
start = Time.now
puts "Recalculating and writing pcaps..."
i = 0
pcaps.each {|pkt|
	p = Packet.parse pkt
	p.recalc
	p.to_f("out.pcap",'a')
	i = i + 1
}
stop = Time.now
puts "#{stop - start} seconds elapsed, #{i} packets written."
# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby


