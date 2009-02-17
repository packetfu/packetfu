
module PacketFu
	
	# The Write class facilitates writing to libpcap files, which is the native file format
	# for packet capture utilities such as tcpdump, Wireshark, and PacketFu::PcapFile.
	#
	# == Example
	#
	#   cap = PacketFu::Capture.new(:start => true)
	#   sleep 10
	#   cap.save
	#   pkt_array = cap.array
	#   PacketFu::Write.a2f(:file => 'pcaps/my_capture.pcap', :array => pkt_array)
	#
	# === array_to_file() Arguments
	#
	#   :filename | :file | :out
	#     The file to write to. If it exists, it will be overwritten. By default, no file will be written.
	#
	#   :array | arr
	#     The array to read packet data from. Note, these should be strings, and not packet objects!
	#
	#   :ts | :timestamp
	#     The starting timestamp. By default, it is the result of Time.now.to_i
	#
	#   :ts_inc | :timestamp_increment
	#     The timestamp increment, in seconds. (Sorry, no usecs yet)
	#
	# == See Also
	#
	# Read, Capture
	class Write

		class << self
			
			# Writes an array of binary data to a libpcap file.
			def array_to_file(args={}) 
				filename = args[:filename] || args[:file] || args[:out] || :nowrite
				arr = args[:arr] || args[:array] || []
				ts = args[:ts] || args[:timestamp] || Time.now.to_f
				ts_inc = args[:ts_inc] || args[:timestamp_increment]
				byte_order = args[:byte_order] || args[:endian] || args[:endianness]
				Read.set_byte_order(byte_order) if [:big, :little].include? byte_order

				time_now = ts
				if arr.class != Array
					raise ArgumentError, "This needs to be an array."
				end
				formatted_packets = []
				arr.each do |pkt|
					time_now += (ts_inc || 1)
					timestamp = [time_now.to_i,((time_now - (time_now.to_i)) * 10**6)].pack("VV")
					this_pkt = PcapPacket.new
					if pkt.class == String
						this_pkt.data = pkt[0,0xffff]
						this_pkt.orig_len = pkt.size
						this_pkt.timestamp.read(timestamp)
					elsif pkt.class == Hash
						this_pkt.data = pkt.values[0][0,0xffff]
						this_pkt.orig_len = pkt.values[0].size
						if ts_inc
							this_pkt.timestamp.read(timestamp)
						else
							this_pkt.timestamp.read(pkt.keys[0])
						end
					else
						raise ArgumentError, "Unknown packet data format, should be either Strings or Hashes of {timestamp=>data}."
					end
					formatted_packets << this_pkt.to_s
				end
				filedata = PcapFile.new
				filedata.read(PcapFile.new.to_s + formatted_packets.join) # Like a cat playing the bass.
				if filename != :nowrite
					File.open(filename.to_s,'w') {|file| file.write filedata}
					# Return [filename, file size, # of packets, initial timestamp, timestamp increment]
					ret = [filename,filedata.to_s.size,arr.size,ts,ts_inc]
				else
					ret = [nil,filedata.to_s.size,arr.size,ts,ts_inc]
				end
			end

			# A synonym for array_to_file()
			def a2f(args={})
				array_to_file(args)
			end

		end

		# IRB tab-completion hack.
		def truth
			"Stranger than fiction" ; true
		end
		#:stopdoc:
		alias_method :array_to_file, :truth
		alias_method :a2f, :truth
		#:startdoc:

	end
end

