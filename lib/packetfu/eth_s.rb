module PacketFu

	# EthOui is the Organizationally Unique Identifier portion of a MAC address, used in EthHeader.
	#
	# See the OUI list at http://standards.ieee.org/regauth/oui/oui.txt
	#
	# ==== Header Definition
	#
	#  bit1     :b0
	#  bit1     :b1
	#  bit1     :b2
	#  bit1     :b3
	#  bit1     :b4
	#  bit1     :b5
	#  bit1     :local
	#  bit1     :multicast
	#  uint16be :oui,      :initial_value => 0x1ac5 # :)
	class EthOui < Struct.new(:b0, :b1, :b2, :b3, :b4, :b5, :local, :multicast, :oui)

		# EthOui is unusual in that the bit values do not (currently) enjoy
		# StructFu typing.
		def initialize(args={})
			args[:local] ||= 0 
			args[:oui] ||= 0x1ac # :)
			args.each_pair {|k,v| args[k] = 0 unless v} 
			super(args[:b0], args[:b1], args[:b2], args[:b3], 
						args[:b4], args[:b5], args[:local], args[:multicast], 
						args[:oui])
		end

		def to_s
			byte = 0
			byte += 0b00000001 if local.to_i == 1
			byte += 0b00000010 if multicast.to_i == 1
			byte += 0b00000100 if b5.to_i == 1
			byte += 0b00001000 if b4.to_i == 1
			byte += 0b00010000 if b3.to_i == 1
			byte += 0b00100000 if b2.to_i == 1
			byte += 0b01000000 if b1.to_i == 1
			byte += 0b10000000 if b0.to_i == 1
			[byte,oui].pack("Cn")
		end

		def read(str)
			return self if str.nil?
			byte = str[0]
			self[:local] = byte & 0b10000000 == 0b10000000 ? 1 : 0
			self[:multicast] = byte & 0b01000000 == 0b01000000 ? 1 : 0
			self[:b5] = byte & 0b00100000 == 0b00100000 ? 1 : 0
			self[:b4] = byte & 0b00010000 == 0b00010000 ? 1 : 0
			self[:b3] = byte & 0b00001000 == 0b00001000 ? 1 : 0
			self[:b2] = byte & 0b00000100 == 0b00000100 ? 1 : 0
			self[:b1] = byte & 0b00000010 == 0b00000010 ? 1 : 0
			self[:b0] = byte & 0b00000001 == 0b00000001 ? 1 : 0
			self[:oui] = str[1,2].unpack("n").first
			self
		end

	end

  # EthNic is the Network Interface Controler portion of a MAC address, used in EthHeader.
	#
	# ==== Header Definition
	#
	#   uint8 :n1
	#   uint8 :n2
	#   uint8 :n3
	#
	class EthNic < Struct.new(:n0, :n1, :n2)

		# EthNic does not enjoy StructFu typing.
		def initialize(args={})
			args.each_pair {|k,v| args[k] = 0 unless v} 
			super(args[:n0], args[:n1], args[:n2])
		end

		def to_s
			[n0,n1,n2].map {|x| x.to_i}.pack("C3")
		end
		
		def read(str)
			return self if str.nil?
			self[:n0], self[:n1], self[:n2] = str[0,3].unpack("C3")
			self
		end

	end

	# EthMac is the combination of an EthOui and EthNic, used in EthHeader.
	#
	# ==== Header Definition
	#
	#   eth_oui :oui  # See EthOui
	#   eth_nic :nic  # See EthOui
	class EthMac < Struct.new(:oui, :nic)

		def initialize(args={})
			super(
			EthOui.new.read(args[:oui]),
			EthNic.new.read(args[:nic]))
		end

		def to_s
			"#{self[:oui]}#{self[:nic]}"
		end

		def read(str)
			return self if str.nil?
			self.oui.read str[0,3]
			self.nic.read str[3,3]
			self
		end

	end

	# EthHeader is a complete Ethernet struct, used in EthPacket. 
	# It's the base header for all other protocols, such as IPHeader, 
	# TCPHeader, etc. 
	#
	# For more on the construction on MAC addresses, see 
	# http://en.wikipedia.org/wiki/MAC_address
	#
	# ==== Header Definition
	#
	#  eth_mac  :eth_dst                             # See EthMac
	#  eth_mac  :eth_src                             # See EthMac
	#  uint16be :eth_proto, :initial_value => 0x0800 # IP 0x0800, Arp 0x0806
	#  rest     :body
	class EthHeader < Struct.new(:eth_dst, :eth_src, :eth_proto, :body)
		include StructFu

		def initialize(args={})
			super(
				EthMac.new.read(args[:eth_dst]),
				EthMac.new.read(args[:eth_src]),
				Int16.new(args[:eth_proto] || 0x0800),
				StructFu::String.new.read(args[:body])
			)
		end

		def eth_dst=(i); typecast(i); end
		def eth_src=(i); typecast(i); end
		def eth_proto=(i); typecast(i); end

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

		def to_s
			self.to_a.map {|x| x.to_s}.join
		end

		def read(str)
			return self if str.nil?
			self[:eth_dst].read str[0,6]
			self[:eth_src].read str[6,6]
			self[:eth_proto].read str[12,2]
			self[:body].read str[14,str.size]
			self
		end

		# Converts a readable MAC (11:22:33:44:55:66) to a binary string. Readable MAC's may be split on colons, dots, 
		# spaces, or underscores.
		#
		# irb> PacketFu::EthHeader.mac2str("11:22:33:44:55:66")
		#
		# #=> "\021\"3DUf"
		def self.mac2str(mac)
			if mac.split(/[:\x2d\x2e\x5f]+/).size == 6
				ret =	mac.split(/[:\x2d\x2e\x20\x5f]+/).collect {|x| x.to_i(16)}.pack("C6")
			else
				raise ArgumentError, "Unkown format for mac address."
			end
			return ret
		end

		# Converts a binary string to a readable MAC (11:22:33:44:55:66). 
		#
		# irb> PacketFu::EthHeader.str2mac("\x11\x22\x33\x44\x55\x66")
		#
		# #=> "11:22:33:44:55:66"
		def self.str2mac(mac='')
			if mac.to_s.size == 6 && mac.kind_of?(::String)
				ret = mac.unpack("C6").map {|x| sprintf("%02x",x)}.join(":")
			end
		end

		# Set the source MAC address in a more readable way.
		def eth_saddr=(mac)
			mac = EthHeader.mac2str(mac)
			self[:eth_src].read mac
			self[:eth_src]
		end

		# Returns a more readable source MAC address.
		def eth_saddr
			EthHeader.str2mac(self[:eth_src].to_s)
		end

		# Set the destination MAC address in a more readable way.
		def eth_daddr=(mac)
			mac = EthHeader.mac2str(mac)
			self[:eth_dst].read mac
			self[:eth_dst]
		end

		# Returns a more readable source MAC address.
		def eth_daddr
			EthHeader.str2mac(self[:eth_dst].to_s)
		end

	end

	class	EthPacket < Packet
		attr_accessor :eth_header

		def initialize(args={})
			@eth_header = EthHeader.new(args).read(args[:eth])
			@headers = [@eth_header]
			super
		end

		# Does nothing, really, since there's no length or
		# checksum to calculate for a straight Ethernet packet.
		def recalc(args={})
			@headers[0].inspect
		end

	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
