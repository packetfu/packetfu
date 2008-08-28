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
		require 'packetfu/lib/capture' 
		require 'packetfu/lib/read' 	
		require 'packetfu/lib/write' 
		require 'packetfu/lib/inject'
		require 'packetfu/lib/pcap'
		@@pcaprub_loaded = true
	rescue LoadError
	end
end


require 'packetfu/lib/packet'
require 'packetfu/lib/invalid'
require 'packetfu/lib/eth'
require 'packetfu/lib/ip'
require 'packetfu/lib/arp'
require 'packetfu/lib/icmp'
require 'packetfu/lib/udp'
require 'packetfu/lib/tcp'
require 'packetfu/lib/ipv6'

# Various often-used utilities.
require 'packetfu/lib/utils'

# A place to keep defaults.
require 'packetfu/lib/config'

#:main:PacketFu
#
#:include:README
#:include:LICENSE

module PacketFu

	# Returns the version.
	def self.version
		"0.0.1-dev" # August 22, 2008
	end

	# A toplevel delegator for Utils.whoami?
	def self.whoami?
		Utils.whoami?
	end

end
