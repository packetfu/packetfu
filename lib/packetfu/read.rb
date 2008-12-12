
module PacketFu

	# The Read class facilitates reading from libpcap files, which is the native file format
	# for packet capture utilities such as tcpdump, Wireshark, and PacketFu::PcapFile.
	#
	# This class requires PcapRub to be loaded (for now).
	#
	# == Example
	#
	#   pkt_array = PacketFu::Read.f2a(:file => 'pcaps/my_capture.pcap')
	#
	# === file_to_array() Arguments
	#
	#   :filename | :file | :out
	#     The file to read from.
	#
	# == See Also
	#
	# Write, Capture
	class Read

		class << self

			# file_to_array() translates a libpcap file into an array of packets.
			# Note, the timestamp keeping business isn't useful for anything yet.
			def file_to_array(args={})
				filename = args[:filename] || args[:file] || args[:out]
				raise ArgumentError, "Need a :filename in string form to read from." if (filename.nil? || filename.class != String)
				f = File.open(filename,'r') {|file| file.read}
				pf = PcapFile.read(f)
				pcap_arr = []
				pf.body.data.each do |pkt|
					if args[:keep_timestamps] || args[:keep_ts] || args[:ts]
						timestamp = [pkt.ts_sec,pkt.ts_usec].pack("VV")
						pcap_arr << {timestamp => pkt.data}
					else
						pcap_arr << pkt.data
					end
				end
				pcap_arr
			end

			# f2a() is equivalent to file_to_array
			def f2a(args={})
				file_to_array(args)
			end

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
		alias_method :file_to_array, :truth
		alias_method :f2a, :truth
		#:startdoc:

	end

end
