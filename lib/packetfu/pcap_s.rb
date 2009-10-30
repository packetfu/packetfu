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
			args[:magic] ||= @int32.new(0xa1b2c3d4)
			args[:ver_major] ||= @int16.new(2)
			args[:ver_minor] ||= @int16.new(4)
			args[:thiszone] ||= @int32.new(0)
			args[:sigfigs] ||= @int32.new(0)
			args[:snaplen] ||= @int32.new(0xffff)
			args[:network] ||= @int32.new(1)
			return args
		end

		def to_s
			self.to_a[1,7].map {|x| x.to_s}.join
		end

		# TODO: read() should determine endianness and switch accordingly.
		# At the moment, the user needs to know endianness ahead of time
		# (defaults to little). This is a bummer, will fix once I get
		# a hold of a big-endian file to test with (not hard).
		def read(str)
			if str[0,4] == self[:magic].to_s || true # always true for now
				self[:magic].read str[0,4]
				self[:ver_major].read str[4,2]
				self[:ver_minor].read str[6,2]
				self[:thiszone].read str[8,4]
				self[:sigfigs].read str[12,4]
				self[:snaplen].read str[16,4]
				self[:network].read str[20,4]
				self
			end
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
			args[:sec] ||= @int32.new(0)
			args[:usec] ||= @int32.new(0)
			return args
		end

		def to_s
			self.to_a[1,2].map {|x| x.to_s}.join
		end

		def read(str)
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
			args[:timestamp] ||= Timestamp.new(:endian => args[:endian])
			args[:incl_len] ||= @int32.new(args[:data].sz)
			args[:orig_len] ||= @int32.new(0)
			args[:data] ||= StructFu::String.new
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

		attr_accessor :endian # probably ought to be read-only but who am i.

		def initialize(args={})
			@endian = args[:endian] || :little
		end

		# Note, read takes in the whole pcap file, since we need to see
		# the magic to know what endianness we're dealing with.
		def read(str)
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
			args[:head] ||= PcapHeader.new(:endian => args[:endian])
			args[:body] ||= PcapPackets.new(:endian => args[:endian])
			return args
		end

		def to_s
			self.to_a[1,2].map {|x| x.to_s}.join
		end

		def read(str)
			self[:head].read str[0,24]
			self[:body].read str
			self
		end

		# file_to_array() translates a libpcap file into an array of packets.
		# Note that this strips out pcap timestamps -- if you'd like to retain
		# timestamps and other libpcap file information, you will want to 
		# use read() instead.
		def file_to_array(args={})
			filename = args[:filename] || args[:file] || args[:f]
			unless (!filename.nil? || filename.class.ancestors.include?(String))
				raise ArgumentError, "Need a :filename for #{self.class}"
			end
			self.read File.open(filename) {|f| f.read}
			self[:body].map {|x| x.data.to_s}
		end

		alias_method :f2a, :file_to_array

		# Prior versions of packetfu had an array_to_file function, where
		# pcaps were story in simple arrays. This seems silly, in retrospect;
		# the strategy now is to store pcaps in memory as regular PcapFile 
		# Structs, so timestamps and what-all can be more easily preserved.
		#
		# Short story is, array_to_file() is out, and to_file() is in.
		def to_file(args={})
			filename = args[:filename] || args[:file] || args[:f]
			unless (!filename.nil? || filename.class.ancestors.include?(String))
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

		# Shorthand method for writing a file with a filename argument.
		def write(filename='out.pcap')
			if filename.class.ancestors.include?(Hash)
				f = filename[:filename] || filename[:file] || filename[:f] || 'out.pcap'
			else
				f = filename.to_s
			end
			self.to_file(:filename => f.to_s, :append => false)
		end

		# Shorthand method for appending to a file by filename. Note, this should
		# remain compatable with http://trac.metasploit.com/changeset/6213/framework3/trunk/lib/packetfu 
		# since that append() wants a hash argument. 
		def append(filename='out.pcap')
			if filename.class.ancestors.include?(Hash)
				f = filename[:filename] || filename[:file] || filename[:f] || 'out.pcap'
			else
				f = filename.to_s
			end
			self.to_file(:filename => f, :append => true)
		end

	end

end
