require 'ipaddr'
module PacketFu

	# Octets implements the addressing scheme for IP.
	#
	# ==== Header Definition
	#
	#  uint8 :o1
	#  uint8 :o2
	#  uint8 :o3
	#  uint8 :o4
	class Octets < Struct.new(:o1, :o2, :o3, :o4)
		include StructFu

		def initialize(args={})
			super(
			Int8.new(args[:o1]),
			Int8.new(args[:o2]),
			Int8.new(args[:o3]),
			Int8.new(args[:o4]))
		end

		def to_s
			self.to_a.map {|x| x.to_s}.join
		end

		def read(str)
			return self if str.nil?
			self[:o1].read str[0,1]
			self[:o2].read str[1,1]
			self[:o3].read str[2,1]
			self[:o4].read str[3,1]
			self
		end

		# Returns an address in dotted-quad format.
		def to_x
			ip_str = [o1, o2, o3, o4].map {|x| x.to_i.to_s}.join('.')
			IPAddr.new(ip_str).to_s
		end

		# Returns an address in numerical format.
		def to_i
			ip_str = [o1, o2, o3, o4].map {|x| x.to_i.to_s}.join('.')
			IPAddr.new(ip_str).to_i
		end

		def read_quad(str)
			read([IPAddr.new(str).to_i].pack("N"))
		end

	end

	# IPHeader is a complete IP struct, used in IPPacket. Most traffic on most networks today is IP-based.
	#
	# For more on IP packets, see http://www.networksorcery.com/enp/protocol/ip.htm
	#
	# ==== Header Definition
	#
	#   bit4     :ip_v,     :initial_value => 4
	#   bit4     :ip_hl,    :initial_value => 5
	#   uint8    :ip_tos,   :initial_value => 0                     # TODO: Break out the bits
	#   uint16be :ip_len,   :initial_value => lambda { ip_calc_len } 
	#   uint16be :ip_id,    :initial_value => lambda { ip_calc_id } # IRL, hardly random. 
	#   uint16be :ip_frag,  :initial_value => 0                     # TODO: Break out the bits
	#   uint8    :ip_ttl,   :initial_value => 0xff                  # Changes per flavor
	#   uint8    :ip_proto, :initial_value => 0x01                  # TCP: 0x06, UDP 0x11, ICMP 0x01
	#   uint16be :ip_sum,   :initial_value => lambda { ip_calc_sum }
	#   octets   :ip_src                                            # No value as this is a MultiValue
	#   octets   :ip_dst                                            # Ditto.
	#   rest     :body
	#
	# Note that IPPackets will always be somewhat incorrect upon initalization, and want
	# an IPHeader#recalc() to become correct before a Packet#to_f or Packet#to_w.
	class IPHeader < Struct.new(:ip_v, :ip_hl, :ip_tos, :ip_len,
															:ip_id, :ip_frag, :ip_ttl, :ip_proto,
															:ip_sum, :ip_src, :ip_dst, :body)
		include StructFu

		def initialize(args={})
			@random_id = rand(0xffff)
			super(
				(args[:ip_v] || 4),
				(args[:ip_hl] || 5),
				Int8.new(args[:ip_tos]),
				Int16.new(args[:ip_len] || ip_calc_len),
				Int16.new(args[:ip_id] || ip_calc_id),
				Int16.new(args[:ip_frag]),
				Int8.new(args[:ip_ttl]),
				Int8.new(args[:ip_proto]),
				Int16.new(args[:ip_sum] || ip_calc_sum),
				Octets.new.read(args[:ip_src] || "\x00\x00\x00\x00"),
				Octets.new.read(args[:ip_dst] || "\x00\x00\x00\x00"),
				StructFu::String.new.read(args[:body])
			)
		end

		def to_s
			byte_v_hl = [(ip_v.to_i << 4) + ip_hl.to_i].pack("C")
			byte_v_hl + (self.to_a[2,10].map {|x| x.to_s}.join)
		end

		def read(str)
			return self if str.nil?
			self[:ip_v] = str[0,1].unpack("C").first >> 4
			self[:ip_hl] = str[0,1].unpack("C").first.to_i & 0x0f
			self[:ip_tos].read(str[1,1])
			self[:ip_len].read(str[2,2])
			self[:ip_id].read(str[4,2])
			self[:ip_frag].read(str[6,2])
			self[:ip_ttl].read(str[8,1])
			self[:ip_proto].read(str[9,1])
			self[:ip_sum].read(str[10,2])
			self[:ip_src].read(str[12,4])
			self[:ip_dst].read(str[16,4])
			self[:body].read(str[20,str.size]) if str.size > 20
			self
		end

		def ip_v=(i); self[:ip_v] = i.to_i; end
		def ip_hl=(i); self[:ip_hl] = i.to_i; end
		def ip_tos=(i); typecast i; end
		def ip_len=(i); typecast i; end
		def ip_id=(i); typecast i; end
		def ip_frag=(i); typecast i; end
		def ip_ttl=(i); typecast i; end
		def ip_proto=(i); typecast i; end
		def ip_sum=(i); typecast i; end
		def ip_src=(i); typecast i; end
		def ip_dst=(i); typecast i; end

		def body=(i) 
			if i.kind_of? ::String
				typecast(i)
			elsif i.kind_of? StructFu
				self[:body] = i
			elsif i.nil?
				self[:body] = StructFu::String.new.read("")
			else
				raise # TODO: Describe this
			end
		end

		# Calulcate the true length of the packet.
		def ip_calc_len
			(ip_hl.to_i * 4) + body.to_s.length
		end

		# Calculate the true checksum of the packet.
		# (Yes, this is the long way to do it, but it's e-z-2-read for mathtards like me.)
		def ip_calc_sum
			checksum =  (((ip_v.to_i  <<  4) + ip_hl.to_i) << 8) + ip_tos.to_i
			checksum += ip_len.to_i
			checksum +=	ip_id.to_i
			checksum += ip_frag.to_i
			checksum +=	(ip_ttl.to_i << 8) + ip_proto.to_i
			checksum += (ip_src.to_i >> 16)
			checksum += (ip_src.to_i & 0xffff)
			checksum += (ip_dst.to_i >> 16)
			checksum += (ip_dst.to_i & 0xffff)
			checksum = checksum % 0xffff 
			checksum = 0xffff - checksum
			checksum == 0 ? 0xffff : checksum
		end

		# Retrieve the IP ID
		def ip_calc_id
			@random_id
		end

		# Sets a more readable IP address. If you wants to manipulate individual octets, 
		# (eg, for host scanning in one network), it would be better use ip_src.o1 through 
		# ip_src.o4 instead. 
		def ip_saddr=(addr)
			ip_src.read_quad(addr)
		end

		# Returns a more readable IP source address. 
		def ip_saddr
			ip_src.to_x
		end

		# Sets a more readable IP address.
		def ip_daddr=(addr)
			ip_dst.read_quad(addr)
		end

		# Returns a more readable IP destination address.
		def ip_daddr
			ip_dst.to_x
		end

		# Translate various formats of IPv4 Addresses to an array of digits.
		def self.octet_array(addr)
			if addr.class == String
				oa = addr.split('.').collect {|x| x.to_i}
			elsif addr.class == Fixnum
				oa = IPAddr.new(addr, Socket::AF_INET).to_s.split('.')
			elsif addr.class == Bignum
				oa = IPAddr.new(addr, Socket::AF_INET).to_s.split('.')
			elsif addr.class == Array
				oa = addr
			else
				raise ArgumentError, "IP Address should be a dotted quad string, an array of ints, or a bignum"
			end
		end

		# Recalculate the calculated IP fields. Valid arguments are:
		#   :all :ip_len :ip_sum :ip_id
		def ip_recalc(arg=:all)
			case arg
			when :ip_len
				self.ip_len=ip_calc_len
			when :ip_sum
				self.ip_sum=ip_calc_sum
			when :ip_id
				@random_id = rand(0xffff)
			when :all
				self.ip_id=		ip_calc_id
				self.ip_len=	ip_calc_len
				self.ip_sum=	ip_calc_sum
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

	end # class IPHeader

	# IPPacket is used to construct IP packets. They contain an EthHeader, an IPHeader, and usually
	# a transport-layer protocol such as UDPHeader, TCPHeader, or ICMPHeader.
	#
	# == Example
	#
	#   require 'packetfu'
	#   ip_pkt = PacketFu::IPPacket.new
	#   ip_pkt.ip_saddr="10.20.30.40"
	#   ip_pkt.ip_daddr="192.168.1.1"
	#   ip_pkt.ip_proto=1
	#   ip_pkt.ip_ttl=64
	#   ip_pkt.ip_payload="\x00\x00\x12\x34\x00\x01\x00\x01"+
	#     "Lovingly hand-crafted echo responses delivered directly to your door."
	#   ip_pkt.recalc 
	#   ip_pkt.to_f('/tmp/ip.pcap')
	#
	# == Parameters
	#
	#   :eth
	#     A pre-generated EthHeader object.
	#   :ip
	#     A pre-generated IPHeader object.
	#   :flavor
	#     TODO: Sets the "flavor" of the IP packet. This might include known sets of IP options, and
	#     certainly known starting TTLs.
	#   :config
	#     A hash of return address details, often the output of Utils.whoami?
	class IPPacket < Packet

		attr_accessor :eth_header, :ip_header

		# Creates a new IPPacket object. 
		def initialize(args={})
			@eth_header = EthHeader.new(args).read(args[:eth])
			@ip_header = IPHeader.new(args).read(args[:ip])
			@eth_header.body=@ip_header

			@headers = [@eth_header, @ip_header]
			super
		end

		# Peek provides summary data on packet contents.
		def peek(args={})
			peek_data = ["I "]
			peek_data << "%-5d" % to_s.size
			peek_data << "%-21s" % "#{ip_saddr}"
			peek_data << "->"
			peek_data << "%21s" % "#{ip_daddr}"
			peek_data << "%23s" % "I:"
			peek_data << "%04x" % ip_id.to_i
			peek_data.join
		end

	end

end # module PacketFu

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
