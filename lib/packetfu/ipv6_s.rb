module PacketFu

	# AddrIpv6 handles addressing for IPv6Header
	#
	# ==== Header Definition
	#
	#
	# uint32be :a1
	# uint32be :a2
	# uint32be :a3
	# uint32be :a4
	class AddrIpv6 < Struct.new(:a1, :a2, :a3, :a4)

		include StructFu

		def initialize(args={})
			super(
				Int32.new(args[:a1]),
				Int32.new(args[:a2]),
				Int32.new(args[:a3]),
				Int32.new(args[:a4]))
		end

		def to_s
			self.to_a.map {|x| x.to_s}.join
		end

		def to_i
			(a1.to_i << 96) + (a2.to_i << 64) + (a3.to_i << 32) + a4.to_i
		end

		def to_x
			IPAddr.new(self.to_i, Socket::AF_INET6).to_s
		end

		def read(str)
			return self if str.nil?
			self[:a1].read str[0,4]
			self[:a2].read str[4,4]
			self[:a3].read str[8,4]
			self[:a4].read str[12,4]
			self
		end

		def read_x(str)
			addr = IPAddr.new(str).to_i
			self[:a1]=Int32.new(addr >> 96)
			self[:a2]=Int32.new((addr & 0x00000000ffffffff0000000000000000) >> 64)
			self[:a3]=Int32.new((addr & 0x0000000000000000ffffffff00000000) >> 32)
			self[:a4]=Int32.new(addr & 0x000000000000000000000000ffffffff)
			self
		end

	end

	# IPv6Header is complete IPv6 struct, used in IPv6Packet. 
	#
	# ==== Header Definition
	#
	#  bit4      :ipv6_v,    :initial_value => 6                        # Versiom
	#  bit8      :ipv6_class                                            # Class
	#  bit20     :ipv6_label                                            # Label
	#  uint16be  :ipv6_len,  :initial_value => lambda { ipv6_calc_len } # Payload length
	#  uint8     :ipv6_next                                             # Next Header
	#  uint8     :ipv6_hop,  :initial_value => 0xff                     # Hop limit
	#  addr_ipv6 :ipv6_src
	#  addr_ipv6 :ipv6_dst
	#  rest      :body
	class IPv6Header < Struct.new(:ipv6_v, :ipv6_class, :ipv6_label,
																:ipv6_len, :ipv6_next, :ipv6_hop,
																:ipv6_src, :ipv6_dst, :body)
		include StructFu

		def initialize(args={})
			super(
				(args[:ipv6_v] || 6),
				(args[:ipv6_class] || 0),
				(args[:ipv6_label] || 0),
				Int16.new(args[:ipv6_len]),
				Int8.new(args[:ipv6_next]),
				Int8.new(args[:ipv6_hop]),
				AddrIpv6.new.read(args[:ipv6_src] || ("\x00" * 16)),
				AddrIpv6.new.read(args[:ipv6_dst] || ("\x00" * 16)),
				StructFu::String.new.read(args[:body])
			)
		end

		def to_s
			bytes_v_class_label = [(self.ipv6_v << 28) +
			 (self.ipv6_class << 20) +
			 self.ipv6_label].pack("N")
			bytes_v_class_label + (self.to_a[3,6].map {|x| x.to_s}.join)
		end

		def read(str)
			return self if str.nil?
			self[:ipv6_v] = str[0,1].unpack("C").first >> 4
			self[:ipv6_class] = (str[0,2].unpack("n").first & 0x0ff0) >> 4
			self[:ipv6_label] = str[0,4].unpack("N").first & 0x000fffff
			self[:ipv6_len].read(str[4,2])
			self[:ipv6_next].read(str[6,1])
			self[:ipv6_hop].read(str[7,1])
			self[:ipv6_src].read(str[8,16])
			self[:ipv6_dst].read(str[24,16])
			self[:body].read(str[40,str.size]) if str.size > 40
			self
		end

		def ipv6_v=(i); self[:ip_v] = i.to_i; end
		def ipv6_v; self[:ipv6_v].to_i; end
		def ipv6_class=(i); self[:ip_class] = i.to_i; end
		def ipv6_class; self[:ipv6_class].to_i; end
		def ipv6_label=(i); self[:ip_label] = i.to_i; end
		def ipv6_label; self[:ipv6_label].to_i; end
		def ipv6_len=(i); typecast i; end
		def ipv6_len; self[:ipv6_len].to_i; end
		def ipv6_next=(i); typecast i; end
		def ipv6_next; self[:ipv6_next].to_i; end
		def ipv6_hop=(i); typecast i; end
		def ipv6_hop; self[:ipv6_hop].to_i; end
		def ipv6_src=(i); typecast i; end
		def ipv6_src; self[:ipv6_src].to_i; end
		def ipv6_dst=(i); typecast i; end
		def ipv6_dst; self[:ipv6_dst].to_i; end

		def ipv6_calc_len
			self[:ipv6_len] = body.to_s.length
		end

		def ipv6_recalc(arg=:all)
			case arg
			when :ipv6_len
				ipv6_calc_len
			when :all
				ipv6_recalc(:len)
			end
		end

		# Presents in a more readable form.
		def ipv6_saddr
			self[:ipv6_src].to_x
		end

		# Takes in a more readable form.
		def ipv6_saddr=(str)
			self[:ipv6_src].read_x(str)
		end

		# Presents in a more readable form.
		def ipv6_daddr
			self[:ipv6_dst].to_x
		end

		# Takes in a more readable form. Leading zero compression is fine, but that's it. :(
		def ipv6_daddr=(str)
			self[:ipv6_dst].read_x(str)
		end

	end # class IPv6Header

	# IPv6Packet is used to construct IPv6 Packets. They contain an EthHeader and an IPv6Header, and in
	# the distant, unknowable future, will take interesting IPv6ish payloads.
	#
	# This mostly complete, but not very useful. It's intended primarily as an example protocol.
	#
	# == Parameters
	#
	#   :eth
	#     A pre-generated EthHeader object.
	#   :ip
	#     A pre-generated IPHeader object.
	#   :flavor
	#     TODO: Sets the "flavor" of the IPv6 packet. No idea what this will look like, haven't done much IPv6 fingerprinting.
	#   :config
	#     A hash of return address details, often the output of Utils.whoami?
	class IPv6Packet < Packet

		attr_accessor :eth_header, :ipv6_header

		def initialize(args={})
			@eth_header = (args[:eth] || EthHeader.new)
			@ipv6_header = (args[:ipv6]	|| IPv6Header.new)
			@eth_header.eth_proto = 0x86dd
			@eth_header.body=@ipv6_header

			@headers = [@eth_header, @ipv6_header]
			super
		end

		# Peek provides summary data on packet contents.
		def peek(args={})
			peek_data = ["6 "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%-31s" % self.ipv6_saddr
			peek_data << "-> "
			peek_data << "%-31s" % self.ipv6_daddr
			peek_data << "  N:"
			peek_data << self.ipv6_next.to_s(16)
			peek_data.join
		end

	end # class IPv6Packet
	
end # module PacketFu
