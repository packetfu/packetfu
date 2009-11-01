$: << File.expand_path(File.dirname(__FILE__))
require "structfu"
require "packetfu/pcap_s"
require "packetfu/eth_s"

module PacketFu
	# Normally, self.size and self.length will refer to the Struct
	# size as an array. It's a hassle to redefine, so this introduces some
	# shorthand to get at the size of the resultant string.
	def sz
		self.to_s.size
	end

	alias len sz
end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
