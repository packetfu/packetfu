
# :title: PacketFu Documentation
# :include: ../README
# :include: ../INSTALL
# :include: ../LICENSE

# $: << File.expand_path(File.dirname(__FILE__))
require "packetfu/structfu"
require "ipaddr"

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

VERSION = "0.3.1" # Jan 11, 2010

	# Returns the current version of PacketFu. Incremented every once in a while.
	def self.version
		PacketFu::VERSION
	end

	# Returns the version in a binary format for easy comparisons.
	def self.binarize_version(str)
		if(str.respond_to?(:split) && str =~ /^[0-9]+(\.([0-9]+)(\.[0-9]+)?)?$/)
			bin_major,bin_minor,bin_teeny = str.split(/\x2e/).map {|x| x.to_i}
			bin_version = (bin_major.to_i << 16) + (bin_minor.to_i << 8) + bin_teeny.to_i
		else
			raise ArgumentError, "Compare version malformed. Should be \x22x.y.z\x22"
		end
	end

	# Returns true if the version is equal to or greater than the compare version.
	# If the current version of PacketFu is "0.3.1" for example:
	#
	#   PacketFu.at_least? "0"     # => true 
	#   PacketFu.at_least? "0.2.9" # => true 
	#   PacketFu.at_least? "0.3"   # => true 
	#   PacketFu.at_least? "0.3.2" # => false 
	#   PacketFu.at_least? "1"     # => false 
	def self.at_least?(str)
		this_version = binarize_version(self.version)
		ask_version = binarize_version(str)
		this_version >= ask_version
	end

	# Returns true if the current version is older than the compare version.
	def self.older_than?(str)
		this_version = binarize_version(self.version)
		ask_version = binarize_version(str)
		this_version < ask_version
	end

	# Returns true if the current version is newer than the compare version.
	def self.newer_than?(str)
		return false if str == self.version
		!self.older_than?(str)
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
