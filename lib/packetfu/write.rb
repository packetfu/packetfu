
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
	#   PacketFu::Write.a2f(:file => 'pcaps/my_capture.pcap', :array => pkt_array, :timestamp => true)
	#
	# === array_to_file() Arguments
	#
	#   :filename | :file | :out
	#     The file to write to. If it exists, it will be overwritten (unless :append is set). 
	#     By default, no file will be written.
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
	#   :byte_order | :endian | :endianness
	#     The endianness of the resulting libpcap file. By default, libcap files are little-endian.
	#   
	#   :append
	#     If :filename exists, then it will be appended to. If :filename is of a different byte order
	#     than what is specified in :byte_order, then it will first be converted, then appended to.
	#
	# == See Also
	#
	# Read, Capture
	class Write

		class << self
			
			def format_packets(args={})
				arr = args[:arr] || args[:array] || []
				ts = args[:ts] || args[:timestamp] || Time.now.to_f
				ts_inc = args[:ts_inc] || args[:timestamp_increment]
				time_now = ts
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
				formatted_packets
			end

			# Writes an array of binary data to a libpcap file.
			def array_to_file(args={})
				filename = args[:filename] || args[:file] || args[:out] || :nowrite
				arr = args[:arr] || args[:array] || []
				ts = args[:ts] || args[:timestamp] || args[:time_stamp] || Time.now.to_f
				ts_inc = args[:ts_inc] || args[:timestamp_increment] || args[:time_stamp_increment]
				byte_order = args[:byte_order] || args[:byteorder] || args[:endian] || args[:endianness] || :little
				append = args[:append]
				Read.set_byte_order(byte_order) if [:big, :little].include? byte_order
				time_now = ts
				if arr.class != Array
					raise ArgumentError, "This needs to be an array."
				end
				formatted_packets = format_packets(args)
				if append and filename != :nowrite and File.readable?(filename) and File.writable?(filename)
					orig_byte_order = Read.get_byte_order(File.open(filename) {|f| f.read(4)})
					if byte_order == orig_byte_order 
						filedata = PcapFile.new.read(File.open(filename) {|f| f.read}).to_s
						filedata += formatted_packets.join
					else
						orig_packets = Read.f2a(:file => filename, :ts => true) # This flips byte_order to the file's
						Read.set_byte_order(byte_order) # This toggles it back.
						formatted_orig_packets = format_packets(:ts => ts, :ts_inc => ts_inc, :arr => orig_packets)
						filedata = PcapFile.new
						filedata.read(PcapFile.new.to_s + (formatted_orig_packets + formatted_packets).join)
					end
				else
					filedata = PcapFile.new
					filedata.read(PcapFile.new.to_s + formatted_packets.join) # Like a cat playing the bass.
				end
				if filename != :nowrite
					File.open(filename.to_s,'w') {|file| file.write filedata}
					# Return [filename, file size, # of new packets, initial timestamp, timestamp increment]
					ret = [filename,filedata.to_s.size,arr.size,ts,ts_inc]
				else
					ret = [nil,filedata.to_s.size,arr.size,ts,ts_inc]
				end
			end

			# A synonym for array_to_file()
			def a2f(args={})
				array_to_file(args)
			end

			# A synonym for array_to_file(), specifically with append set. This is to ensure functional
			# compatability with http://trac.metasploit.com/changeset/6213/framework3/trunk/lib/packetfu
			def append(args={})
				array_to_file(args.merge(:append => true))
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

