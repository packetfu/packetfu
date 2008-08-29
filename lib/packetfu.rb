if VERSION < "1.8.6"
	raise RuntimeError, "Ruby not at a minimum version of 1.8.6"
end

require 'bindata'

if BinData::VERSION < "0.9.2"
	raise LoadError, "BinData not at a minimum version of 0.9.2"
end

require 'ipaddr'
require 'singleton'

module PacketFu
	@@pcaprub_loaded = false
	begin
		require 'pcaprub'
		if Pcap.version < "0.8-dev"
			raise LoadError, "PcapRub not at a minimum version of 0.8-dev"
		end
		require 'packetfu/capture' 
		require 'packetfu/read' 	
		require 'packetfu/inject'
		@@pcaprub_loaded = true
	rescue LoadError
	end
end

# Doesn't require PcapRub
require 'packetfu/pcap'
require 'packetfu/write' 

# Packet crafting/parsing goodness.
require 'packetfu/packet'
require 'packetfu/invalid'
require 'packetfu/eth'
require 'packetfu/ip'
require 'packetfu/arp'
require 'packetfu/icmp'
require 'packetfu/udp'
require 'packetfu/tcp'
require 'packetfu/ipv6'

# Various often-used utilities.
require 'packetfu/utils'

# A place to keep defaults.
require 'packetfu/config'

#:main:PacketFu
#
#:include:../README
#:include:../LICENSE

module PacketFu

	# Returns the version.
	def self.version
		"0.0.1-dev" # August 22, 2008
	end

end
