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

# Change these to taste. None of these globals are required, 
# for normal functionality, so nuke them in the event of a 
# name conflict. They are likely to be removed anyway in
# future stable versions, since libraries that declare globals
# are kind of lame.

$packetfu_pcapfile = '/tmp/out.pcap'	# Default file to write to.
$packetfu_iface = 'eth0'							# Default interface to capture/inject from/to

$packetfu_do_whoami = true # Set to false if you don't want to start your sessions by identifying yourself.
$packetfu_iam = {} # Where your native eth_src and ip_src go for your default interface

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

	# Find the local default Ethernet and IP address, and set the 
	# global <b>$packetfu_iam</b> variable accordingly. This is accomplished
	# by listening for, then generating, a random UDP packet. This packet
	# will fire off on load unless <b>$packetfu_do_whoami == false</b>
	#
	# === Example
	#
	#   PacketFu::whoami? # => {:ip_src=>"\n\n\n\003", :eth_saddr=>"00:03:47:bf:55:3c", :eth_src=>"\000\003G\277U<", :ip_saddr=>"10.10.10.3"}
	#
	#
	def self.whoami?
		Capture.whoami?(:save => true)
	end

	whoami? if $packetfu_do_whoami and Process.euid.zero?

end
