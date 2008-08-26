
module PacketFu

	# The Inject class handles injecting arrays of binary data on the wire.
	#
	# To inject single packets, use PacketFu::Packet.to_w() instead.
	class Inject 
		attr_accessor :array, :stream, :show_live # Leave these public and open.
		attr_reader :iface, :snaplen, :promisc, :timeout # Cant change after the init.

		def initialize(args={})
			@array = [] # Where the packet array goes.
			@stream = [] # Where the stream goes.
			@iface = args[:iface] || $packetfu_iface || 'eth0' # Sometimes should be wlan0 or eth1	
			@snaplen = args[:snaplen] || 0xffff
			@promisc = args[:promisc] || false # Sensible for some Intel wifi cards
			@timeout = args[:timeout] || 1
			@show_live = nil
		end

		# Takes an array, and injects them onto an interface. Note that
		# complete packets (Ethernet headers on down) are expected. 
		#
		# === Parameters
		#
		#   :array || arr
		#    An array of binary data (usually packet.to_s style).
		#   :int || sleep
		#    Number of seconds to sleep between injections (in float format)
		#   :show_live || :live
		#    If true, puts data about what was injected to stdout.
		#
		# === Example
		#
		#  inj = PacketFu::Inject.new
		#  inj.array_to_wire(:array => [pkt1, pkt2, pkt3], :sleep => 0.1)
		#
		def array_to_wire(args={})
			pkt_array = args[:array] || args[:arr] || @array
			interval = args[:int] || args[:sleep]
			show_live = args[:show_live] || args[:live] || @show_live

			@stream = Pcap.open_live(@iface,@snaplen,@promisc,@timeout)
			pkt_count = 0
			pkt_array.each do |pkt|
				@stream.inject(pkt)
				sleep interval if interval
				pkt_count +=1
				puts "Sent Packet \##{pkt_count} (#{pkt.size})" if show_live
			end
			# Return # of packets sent, array size, and array total size 
			[pkt_count, pkt_array.size, pkt_array.join.size]
		end

		# Equivalent to array_to_wire
		def a2w(args={})
			array_to_wire(args)
		end

		# Equivalent to array_to_wire
		def inject(args={})
			array_to_wire(args)
		end

		# IRB tab-completion hack.
		#--
		# This silliness is so IRB's tab-completion works for my class methods
		# when those methods are called without first instantiating. (I like
		# tab completion a lot). The alias_methods make sure they show up
		# as instance methods, but but when you call them, you're really 
		# calling the class methods. Tricksy!
		def truth
			"You can't handle the truth" ; true
		end
		
		#:stopdoc:
		alias_method :inject, :truth
		alias_method :a2w, :truth
		#:startdoc:

	end
end

