require 'packetfu'
infile = ARGV[0] || "in.pcap"
outfile = ARGV[1] || "out.pcap"
puts "Reading packets from #{infile}, writing to #{outfile}..."
pkts = PacketFu::Read.f2a(:file => infile, :ts => true)
chomped_pkts = []
puts "Parsing out the FCS..."
pkts.each_with_index { |p,i|
	value = p[p.keys.first]
	p[p.keys.first] = PacketFu::Packet.parse(value,:strip => true).to_s
	print "." if i % 10 == 0
	STDOUT.flush
	chomped_pkts << p
}
puts "Writing #{outfile}..."
PacketFu::Write.a2f(:file => outfile, :array => chomped_pkts)

