#!/usr/bin/env ruby

module StructFu

	def set_endianness(e=nil)
		unless [:little, :big].include? e
			raise ArgumentError, "Unknown endianness for #{self.class}" 
		end
		@int32 = e == :little ? Int32le : Int32be
		@int16 = e == :little ? Int16le : Int16be
		return e
	end

	def sz
		self.to_s.size
	end

end

module PacketFu

	class PcapHeader < Struct.new(:endian, :magic, :ver_major, :ver_minor,
																:thiszone, :sigfigs, :snaplen, :network)
		include StructFu

		def initialize(args={})
			set_endianness(args[:endian] ||= :little)
			init_fields(args) 
			super(args[:endian], args[:magic], args[:ver_major], 
						args[:ver_minor], args[:thiszone], args[:sigfigs], 
						args[:snaplen], args[:network])
		end
		
		def init_fields(args={})
			args[:magic] = @int32.new(args[:magic] || 0xa1b2c3d4)
			args[:ver_major] = @int16.new(args[:ver_major] || 2)
			args[:ver_minor] ||= @int16.new(args[:ver_minor] || 4)
			args[:thiszone] ||= @int32.new(args[:thiszone])
			args[:sigfigs] ||= @int32.new(args[:sigfigs])
			args[:snaplen] ||= @int32.new(args[:snaplen] || 0xffff)
			args[:network] ||= @int32.new(args[:network] || 1)
			return args
		end

		def to_s
			self.to_a[1,7].map {|x| x.to_s}.join
		end

		# TODO: Create a test case for both endian file types, and incidentally
		# convert from one to another. Right now, if you read in a big-endian
		# file, you'll write a big-endian file.
		def read(str)
			return self if str.nil?
			if str[0,4] == self[:magic].to_s || true # TODO: raise if it's not magic.
				self[:magic].read str[0,4]
				self[:ver_major].read str[4,2]
				self[:ver_minor].read str[6,2]
				self[:thiszone].read str[8,4]
				self[:sigfigs].read str[12,4]
				self[:snaplen].read str[16,4]
				self[:network].read str[20,4]
			end
			self
		end

	end

	class Timestamp < Struct.new(:endian, :sec, :usec)
		include StructFu

		def initialize(args={})
			set_endianness(args[:endian] ||= :little)
			init_fields(args)
			super(args[:endian], args[:sec], args[:usec])
		end

		def init_fields(args={})
			args[:sec] = @int32.new(args[:sec])
			args[:usec] = @int32.new(args[:usec])
			return args
		end

		def to_s
			self.to_a[1,2].map {|x| x.to_s}.join
		end

		def read(str)
			return self if str.nil?
			self[:sec].read str[0,4]
			self[:usec].read str[4,4]
			self
		end

	end

	class PcapPacket < Struct.new(:endian, :timestamp, :incl_len,
															 :orig_len, :data)
		include StructFu
		def initialize(args={})
			set_endianness(args[:endian] ||= :little)
			init_fields(args)
			super(args[:endian], args[:timestamp], args[:incl_len],
					 args[:orig_len], args[:data])
		end

		def init_fields(args={})
			args[:timestamp] = Timestamp.new(:endian => args[:endian]).read(args[:timestamp])
			args[:incl_len] = args[:incl_len].nil? ? @int32.new(args[:data].to_s.size) : @int32.new(args[:incl_len])
			args[:orig_len] = @int32.new(args[:orig_len])
			args[:data] = StructFu::String.new.read(args[:data])
		end

		def to_s
			self.to_a[1,4].map {|x| x.to_s}.join
		end

		def read(str)
			self[:timestamp].read str[0,8]
			self[:incl_len].read str[8,4]
			self[:orig_len].read str[12,4]
			self[:data].read str[16,self[:incl_len].to_i]
			self
		end

	end

	class PcapPackets < Array

		include StructFu

		attr_accessor :endian # probably ought to be read-only but who am i.

		def initialize(args={})
			@endian = args[:endian] || :little
		end

		# Note, read takes in the whole pcap file, since we need to see
		# the magic to know what endianness we're dealing with.
		def read(str)
			return self if str.nil?
			magic = "\xa1\xb2\xc3\xd4"
			if str[0,4] == magic
				@endian = :big
			elsif str[0,4] == magic.reverse
				@endian = :little
			else
				raise ArgumentError, "Unknown file format for #{self.class}"
			end
			body = str[24,str.size]
			while body.size > 16 # TODO: catch exceptions on malformed packets at end
				p = PcapPacket.new(:endian => @endian)
				p.read(body)
				self<<p
				body = body[p.sz,body.size]
			end
		self
		end

	end

	# PcapFile is a complete libpcap file struct, made up of two elements, a 
	# PcapHeader and PcapPackets.
	#
	# See http://wiki.wireshark.org/Development/LibpcapFileFormat
	class PcapFile < Struct.new(:endian, :head, :body)
		include StructFu

		def initialize(args={})
			init_fields(args)
			super(args[:endian], args[:head], args[:body])
		end

		def init_fields(args={})
			args[:head] = PcapHeader.new(:endian => args[:endian]).read(args[:head])
			args[:body] = PcapPackets.new(:endian => args[:endian]).read(args[:body])
			return args
		end

		def to_s
			self.to_a[1,2].map {|x| x.to_s}.join
		end

		def clear
			self[:body].clear
		end

		def read(str)
			self[:head].read str[0,24]
			self[:body].read str
			self
		end

		def read!(str)
			clear	
			self.read str
		end

		def readfile(file)
			f = File.open(file) {|f| f.read}
			self.read! f
		end

		# file_to_array() translates a libpcap file into an array of packets.
		# Note that this strips out pcap timestamps -- if you'd like to retain
		# timestamps and other libpcap file information, you will want to 
		# use read() instead.
		#
		# Note, invoking this requires the somewhat clumsy sytax of,
		# PcapFile.new.file_to_array(:f => 'filename.pcap')
		def file_to_array(args={})
			filename = args[:filename] || args[:file] || args[:f]
			if filename
				self.read! File.open(filename) {|f| f.read}
			end
			if args[:keep_timestamps] || args[:keep_ts] || args[:ts]
				self[:body].map {|x| {x.timestamp.to_s => x.data.to_s} }
			else
				self[:body].map {|x| x.data.to_s}
			end
		end

		alias_method :f2a, :file_to_array

		def array_to_file(args={})
			if args.kind_of? Hash
				filename = args[:filename] || args[:file] || args[:f]
				arr = args[:array] || args[:arr] || args[:a]
				ts = args[:timestamp] || args[:ts] || Time.now.to_i
				ts_inc = args[:timestamp_increment] || args[:ts_inc] || 1
				append = !!args[:append]
			elsif args.kind_of? Array
				arr = args
				filename = append = nil
			else
				raise ArgumentError, "Unknown argument. Need either a Hash or Array."
			end
			unless arr.kind_of? Array
				raise ArgumentError, "Need an array to read packets from"
			end
			arr.each_with_index do |p,i|
				if p.kind_of? Hash # Binary timestamps are included
					this_ts = p.keys.first
					this_incl_len = p.values.first.size
					this_orig_len = this_incl_len
					this_data = p.values.first
				else # it's an array
					this_ts = Timestamp.new(:endian => self[:endian], :sec => ts + (ts_inc * i)).to_s
					this_incl_len = p.to_s.size
					this_orig_len = this_incl_len
					this_data = p.to_s
				end
				this_pkt = PcapPacket.new({:endian => self[:endian],
																  :timestamp => this_ts,
																	:incl_len => this_incl_len,
																	:orig_len => this_orig_len,
																	:data => this_data }
																 )
				self[:body] << this_pkt
			end
			if filename
				self.to_f(:filename => filename, :append => append)
			else
				self
			end
		end

		alias_method :a2f, :array_to_file

		def array_to_file!(arr)
			clear
			array_to_file(arr)
		end

		alias_method :a2f!, :array_to_file!

		def to_file(args={})
			filename = args[:filename] || args[:file] || args[:f]
			unless (!filename.nil? || filename.kind_of?(String))
				raise ArgumentError, "Need a :filename for #{self.class}"
			end
			append = args[:append]
			if append
				File.open(filename,'a') {|file| file.write(self.body.to_s)}
			else
				File.open(filename,'w') {|file| file.write(self.to_s)}
			end
			[filename, self.body.sz, self.body.size]
		end

		alias_method :to_f, :to_file

		# Shorthand method for writing a file with a filename argument.
		def write(filename='out.pcap')
			if filename.kind_of?(Hash)
				f = filename[:filename] || filename[:file] || filename[:f] || 'out.pcap'
			else
				f = filename.to_s
			end
			self.to_file(:filename => f.to_s, :append => false)
		end

		def append(filename='out.pcap')
			if filename.kind_of?(Hash)
				f = filename[:filename] || filename[:file] || filename[:f] || 'out.pcap'
			else
				f = filename.to_s
			end
			self.to_file(:filename => f, :append => true)
		end

	end

end

module PacketFu

	# Read is largely deprecated. It was current in PacketFu 0.2.0, but isn't all that useful
	# in 0.3.0 and beyond. Expect it to go away completely by version 1.0. So, the main use
	# of this class is to learn how to do exactly the same things using the PcapFile object.
	class Read

		class << self

			# get_byte_order() reads the magic string of a pcap file, and determines
			# if it's :little or :big endian.
			def get_byte_order(pcap_file)
				byte_order = ((pcap_file[0,4] == "\xd4\xc3\xb2\xa1") ? :little : :big)
				return byte_order
			end

			# set_byte_order: pretty much totally deprecated.
			def set_byte_order(byte_order)
				PacketFu.instance_variable_set("@byte_order",byte_order)
				return true
			end

			# A wrapper for PcapFile#file_to_array, but only returns the array. Actually
			# using the PcapFile object is going to be more useful.
			def file_to_array(args={})
				filename = args[:filename] || args[:file] || args[:out]
				raise ArgumentError, "Need a :filename in string form to read from." if (filename.nil? || filename.class != String)
				PcapFile.new.file_to_array(args)
			end

			alias_method :f2a, :file_to_array

		end

	end

end

module PacketFu

	# Write is largely deprecated. It was current in PacketFu 0.2.0, but isn't all that useful
	# in 0.3.0 and beyond. Expect it to go away completely by version 1.0, as working with
	# PacketFu::PcapFile directly is generally going to be more rewarding.
	class Write

		class << self

			# format_packets: Pretty much totally deprecated.
			def format_packets(args={})
				arr = args[:arr] || args[:array] || []
				ts = args[:ts] || args[:timestamp] || Time.now.to_i
				ts_inc = args[:ts_inc] || args[:timestamp_increment]
				pkts = PcapFile.new.array_to_file(:endian => PacketFu.instance_variable_get("@byte_order"),
																					:arr => arr,
																					:ts => ts,
																					:ts_inc => ts_inc)
				pkts.body
			end

			# array_to_file is a largely deprecated function for writing arrays of pcaps to a file.
			# Use PcapFile#array_to_file instead.
			def array_to_file(args={})
				filename = args[:filename] || args[:file] || args[:out] || :nowrite
				arr = args[:arr] || args[:array] || []
				ts = args[:ts] || args[:timestamp] || args[:time_stamp] || Time.now.to_f
				ts_inc = args[:ts_inc] || args[:timestamp_increment] || args[:time_stamp_increment]
				byte_order = args[:byte_order] || args[:byteorder] || args[:endian] || args[:endianness] || :little
				append = args[:append]
				Read.set_byte_order(byte_order) if [:big, :little].include? byte_order
				pf = PcapFile.new
				pf.array_to_file(:endian => PacketFu.instance_variable_get("@byte_order"),
												 :arr => arr,
												 :ts => ts,
												 :ts_inc => ts_inc)
				if filename && filename != :nowrite
					if append
						pf.append(filename)
					else
						pf.write(filename)
					end
					return [filename,pf.to_s.size,arr.size,ts,ts_inc]
				else
					return [nil,pf.to_s.size,arr.size,ts,ts_inc]
				end

			end

			alias_method :a2f, :array_to_file

			def append(args={})
				array_to_file(args.merge(:append => true))
			end

		end

	end

end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
