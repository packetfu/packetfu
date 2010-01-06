$: << File.expand_path(File.dirname(__FILE__))
require "structfu"
require "ipaddr"
require "singleton"

# require "rubygems"
# require "ruby-prof"

module PacketFu

	# Sets the expected byte order for a pcap file. See PacketFu::Read.set_byte_order
	@byte_order = :little

	# Checks if pcaprub is loaded correctly.
	@@pcaprub_loaded = false
	
	# PacketFu works best with Pcaprub version 0.8-dev, now made available
	# with this distribution. Say, can Mac users give me some idea of how
	# to install on your hipster youth-oriented Bay Area grunge OS?
  def self.pcaprub_platform_require
    if File.directory?("C:\\")
			require 'pcaprub_win32/pcaprub'
      @@pcaprub_loaded = true 
    else
			require 'pcaprub' # Linux and Mac (Apple uses pcaprub.bundle, Linux uses pcaprub.so)
      @@pcaprub_loaded = true if($".grep(/pcaprub\./).size > 0)
    end
  end

	begin
		pcaprub_platform_require
		if Pcap.version !~ /[0-9]\.[7-9][0-9]?(-dev)?/ # Regex for 0.7-dev and beyond.
      @@pcaprub_loaded = false # Don't bother with broken versions
			raise LoadError, "PcapRub not at a minimum version of 0.8-dev"
		end
		# require 'packetfu/capture' 
		# require 'packetfu/inject'
	rescue LoadError
	end
end

require "packetfu/pcap_s"
# require "packetfu/write" # Need to reimplement
# require "packetfu/read" # Need to reimplement
require "packetfu/packet_s"
require "packetfu/invalid_s"
# This order is desperately important. Should fix this so everyone
# has a chance to require the stuff they need.
require "packetfu/eth_s"
require "packetfu/ip_s" 
require "packetfu/arp_s"
require "packetfu/icmp_s"
require "packetfu/udp_s"
require "packetfu/tcp_s"
# require 'packetfu/ipv6'
# require 'packetfu/utils'
# require 'packetfu/config'

module PacketFu

	def self.version
		"0.3.0" # Jan 5, 2010
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
