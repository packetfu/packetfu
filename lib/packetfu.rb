$: << File.expand_path(File.dirname(__FILE__))
require "packetfu/structfu"
require "ipaddr"
require "singleton"

# require "rubygems"
# require "ruby-prof"

module PacketFu

	# Sets the expected byte order for a pcap file. See PacketFu::Read.set_byte_order
	@byte_order = :little

	# Checks if pcaprub is loaded correctly.
	@@pcaprub_loaded = false
	
	# PacketFu works best with Pcaprub version 0.8-dev (at least)
	#
	# TODO: Could this be better? See:
	# http://blog.emptyway.com/2009/11/03/proper-way-to-detect-windows-platform-in-ruby/
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
		require "packetfu/capture" 
		require "packetfu/inject"
	rescue LoadError
	end
end

require "packetfu/pcap"
require "packetfu/packet"
require "packetfu/invalid"
require "packetfu/eth"
require "packetfu/ip" 
require "packetfu/arp"
require "packetfu/icmp"
require "packetfu/udp"
require "packetfu/tcp"
require "packetfu/ipv6" # This is pretty minimal.
require "packetfu/utils"
require "packetfu/config"

module PacketFu

	def self.version
		"0.3.0" # Jan 5, 2010
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
