
module PacketFu

	class Inject 
		attr_accessor :array, :stream, :show_live # Leave these public and open.
		attr_reader :iface, :snaplen, :promisc, :timeout # Cant change after the init.

		def initialize(args={})
			@array = [] # Where the packet array goes.
			@stream = [] # Where the stream goes.
			@iface = args[:iface] || 'eth0' # Sometimes should be wlan0 or eth1	
			@snaplen = args[:snaplen] || 0xffff
			@promisc = args[:promisc] || false # Sensible for some Intel wifi cards
			@timeout = args[:timeout] || 1
			@show_live = nil
		end

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

		def a2w(args={})
			array_to_wire(args)
		end

		def inject(args={})
			array_to_wire(args)
		end

	end
end

