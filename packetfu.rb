if VERSION < "1.8.6"
	raise RuntimeError, "Ruby not at a minimum version of 1.8.6"
end

require 'pcaprub'

if Pcap.version < "0.8-dev"
	raise RuntimeError, "PcapRub not at a minimum version of 0.8-dev"
end

require 'bindata'

if BinData::VERSION < "0.9.2"
	raise RuntimeError, "BinData not at a minimum version of 0.9.2"
end

require 'ipaddr'
require 'singleton'

require 'packetfu/lib/capture'
require 'packetfu/lib/read' 
require 'packetfu/lib/write'
require 'packetfu/lib/inject'
require 'packetfu/lib/pcap'

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

# = PacketFu
#
# A library for reading a writing packets to an interface or to a libpcap-formatted file.
# It is maintained at http://code.google.com/p/packetfu/
#
# == Installation
#
# PacketFu should live somewhere in your path. I haven't decided yet
# on packaging, mainly because I need to figure out what works best
# for Linux/Win/OSX (and FreeBSD, and Solaris maybe); your best bet 
# is to just drop it into /usr/local/lib/site_ruby/1.8 or where ever 
# you install bindata to.
#
# == Requirements
#
# BinData: http://bindata.rubyforge.org
#
# PcapRub: http://www.metasploit.com/svn/framework3/trunk/external/pcaprub
#
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
