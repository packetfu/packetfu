
# :title: PacketFu Documentation
# :include: ../README
# :include: ../INSTALL
# :include: ../LICENSE

cwd = File.expand_path(File.dirname(__FILE__))

$: << cwd

require "packetfu/structfu"
require "ipaddr"
require 'rubygems' if RUBY_VERSION =~ /^1\.[0-8]/

module PacketFu

	# Sets the expected byte order for a pcap file. See PacketFu::Read.set_byte_order
	@byte_order = :little

	# Checks if pcaprub is loaded correctly.
	@pcaprub_loaded = false

	# PacketFu works best with Pcaprub version 0.8-dev (at least)
	# The current (Aug 01, 2010) pcaprub gem is 0.9, so should be fine.
	def self.pcaprub_platform_require
		begin
			require 'pcaprub'
		rescue LoadError
			return false
		end
		@pcaprub_loaded = true 
	end

	pcaprub_platform_require
	if @pcaprub_loaded
		if Pcap.version !~ /[0-9]\.[7-9][0-9]?(-dev)?/ # Regex for 0.7-dev and beyond.
			@pcaprub_loaded = false # Don't bother with broken versions
			raise LoadError, "PcapRub not at a minimum version of 0.8-dev"
		end
		require "packetfu/capture" 
		require "packetfu/inject"
	end

	def self.add_packet_class(klass)
		@packet_classes ||= []
		@packet_classes << klass
		@packet_classes.sort! {|x,y| x.name <=> y.name}
	end

	def self.packet_classes
		@packet_classes || []
	end

	def self.packet_prefixes
		return [] unless @packet_classes
		@packet_classes.map {|p| p.to_s.split("::").last.to_s.downcase.gsub(/packet$/,"")}
	end

	def self.pcaprub_loaded?
		@pcaprub_loaded
	end

end

def require_protos(cwd)
	protos_dir = File.join(cwd, "packetfu", "protos")
	Dir.new(protos_dir).each do |fname|
		next unless fname[/\.rb$/]
		begin 
			require File.join(protos_dir,fname)
		rescue
			warn "Warning: Could not load `#{fname}'. Skipping."
		end
	end
end

require "packetfu/version"
require "packetfu/pcap"
require "packetfu/packet"
require_protos(cwd)
require "packetfu/utils"
require "packetfu/config"

module PacketFu

	# Returns an array of classes defined in PacketFu
	def self.classes
		constants.map { |const| const_get(const) if const_get(const).kind_of? Class}.compact
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
