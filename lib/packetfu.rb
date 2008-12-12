if VERSION < "1.8.6"
	raise RuntimeError, "Ruby not at a minimum version of 1.8.6"
end

require 'bindata'

# Happy day, unforking BinData.
if BinData::VERSION < "0.9.3"
	raise LoadError, "BinData not at version 0.9.3 or later."
end

require 'ipaddr'
require 'singleton'

module PacketFu
	@@pcaprub_loaded = false
  
  def self.pcaprub_platform_require
    if File.directory?("C:\\")
      require 'pcaprub_win32/pcaprub'
      @@pcaprub_loaded = true
    elsif File.directory?("/usr")
       require 'pcaprub' # Presumes you already have it. Apple, does this work for you?
       @@pcaprub_loaded = true
    else
      @@pcaprub_loaded = false # Still false
    end
  end
  
	begin
		pcaprub_platform_require
		if Pcap.version < "0.8-dev"
      @@pcaprub_loaded = false # Don't bother with broken versions
			raise LoadError, "PcapRub not at a minimum version of 0.8-dev"
		end
		require 'packetfu/capture' 
		require 'packetfu/read' 	
		require 'packetfu/inject'
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
		"0.1.0" # September 13, 2008
	end

end
