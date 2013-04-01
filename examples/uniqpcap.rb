# Uniqpcap.rb takes a pcap file, strips out duplicate packets, and 
# writes them to a file.
#
# The duplicate pcap problem is common when I'm capturing 
# traffic to/from a VMWare image, for some reason.
#
# Currently, the timestamp information is lost due to PcapRub's 
# file read. For me, this isn't a big deal. Future versions 
# will deal with timestamps correctly.
require './examples' # For path setting slight-of-hand
require 'packetfu'

in_array = PacketFu::Read.f2a(:file => ARGV[0])
puts PacketFu::Write.a2f(:file => "uniq-" + ARGV[0], :arr => in_array.uniq).inspect

