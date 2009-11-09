module PacketFu

	# ARPHeader is a complete ARP struct, used in ARPPacket. 
	#
	# ARP is used to discover the machine address of nearby devices.
	#
	# See http://www.networksorcery.com/enp/protocol/arp.htm for details.
	#
	# ==== Header Definition
	#
	#	 uint16be :arp_hw,        :initial_value => 1      # Ethernet
	#	 uint16be :arp_proto,     :initial_value => 0x0800 # IP
	#	 uint8    :arp_hw_len,    :initial_value => 6
	#	 uint8    :arp_proto_len, :initial_value => 4
	#	 uint16be :arp_opcode,    :initial_value => 1      # 1: Request, 2: Reply, 3: Request-Reverse, 4: Reply-Reverse
	#	 eth_mac  :arp_src_mac                             # From eth.rb
	#	 octets   :arp_src_ip                              # From ip.rb
	#	 eth_mac  :arp_dst_mac                             # From eth.rb
	#	 octets   :arp_dst_ip                              # From ip.rb
	#	 rest     :body
	#
	class ARPHeader < Struct.new(:arp_hw, :arp_proto, :arp_hw_len,
															 :arp_proto_len, :arp_opcode,
															 :arp_src_mac, :arp_src_ip,
															 :arp_dst_mac, :arp_dst_ip,
															 :body)
		include StructFu

		# XXX this is a wee bit wrong, so fix and test this!
		def initialize(args={})
			super( 
				Int16.new(args[:arp_hw] || 1), 
				Int16.new(args[:arp_proto] ||0x0800),
				Int8.new(args[:arp_hw_len] || 6), 
				Int8.new(args[:arp_proto_len] || 4), 
				Int16.new(args[:arp_opcode] || 1),
				EthMac.new.read(args[:arp_src_mac]),
				Octets.new.read(args[:arp_src_ip]), 
				EthMac.new.read(args[:arp_dst_mac]),
				Octets.new.read(args[:arp_dst_ip]),
				StructFu::String.new.read(args[:body])
			)
		end

		def to_s
			self.to_a.map {|x| x.to_s}.join
		end

		def read(str)
			return self if str.nil?
			self[:arp_hw].read(str[0,2])
			self[:arp_proto].read(str[2,2])
			self[:arp_hw_len].read(str[4,1])
			self[:arp_proto_len].read(str[5,1])
			self[:arp_opcode].read(str[6,2])
			self[:arp_src_mac].read(str[8,6])
			self[:arp_src_ip].read(str[14,4])
			self[:arp_dst_mac].read(str[18,6])
			self[:arp_dst_ip].read(str[24,4])
			self[:body].read(str[28,str.size])
			self
		end

		# This bit should be easier to write, but hey.
		def arp_hw=(i); typecast i; end
		def arp_proto=(i); typecast i; end
		def arp_hw_len=(i); typecast i; end
		def arp_proto_len=(i); typecast i; end
		def arp_opcode=(i); typecast i; end
		def arp_src_mac=(i); typecast i; end
		def arp_src_ip=(i); typecast i; end
		def arp_dst_mac=(i); typecast i; end
		def arp_dst_ip=(i); typecast i; end

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

		# Set the source MAC address in a more readable way.
		def arp_saddr_mac=(mac)
			mac = EthHeader.mac2str(mac)
			self.arp_src_mac.read(mac)
			self.arp_src_mac
		end

		# Returns a more readable source MAC address.
		def arp_saddr_mac
			EthHeader.str2mac(self.arp_src_mac.to_s)
		end

		# Set the destination MAC address in a more readable way.
		def arp_daddr_mac=(mac)
			mac = EthHeader.mac2str(mac)
			self.arp_dst_mac.read(mac)
			self.arp_dst_mac
		end

		# Returns a more readable source MAC address.
		def arp_daddr_mac
			EthHeader.str2mac(self.arp_dst_mac.to_s)
		end

		# Sets a more readable source IP address. 
		def arp_saddr_ip=(addr)
			arp_src_ip.read_quad(addr)
		end

		# Returns a more readable source IP address. 
		def arp_saddr_ip
			arp_src_ip.to_x
		end

		# Sets a more readable destination IP address.
		def arp_daddr_ip=(addr)
			arp_dst_ip.read_quad(addr)
		end
		
		# Returns a more readable destination IP address.
		def arp_daddr_ip
			arp_dst_ip.to_x
		end

	end # class ARPHeader

	# ARPPacket is used to construct ARP packets. They contain an EthHeader and an ARPHeader.
	# == Example
	#
  #  require 'packetfu'
	#  arp_pkt = PacketFu::ARPPacket.new(:flavor => "Windows")
	#  arp_pkt.arp_saddr_mac="00:1c:23:44:55:66"  # Your hardware address
	#  arp_pkt.arp_saddr_ip="10.10.10.17"  # Your IP address
	#  arp_pkt.arp_daddr_ip="10.10.10.1"  # Target IP address
	#  arp_pkt.arp_opcode=1  # Request
	# 
	#  arp_pkt.to_w('eth0')	# Inject on the wire. (requires root)
  #  arp_pkt.to_f('/tmp/arp.pcap') # Write to a file.
	#
	# == Parameters
	#
	#  :flavor
	#   Sets the "flavor" of the ARP packet. Choices are currently:
	#     :windows, :linux, :hp_deskjet 
	#  :eth
	#   A pre-generated EthHeader object. If not specified, a new one will be created.
	#  :arp
	#   A pre-generated ARPHeader object. If not specificed, a new one will be created.
	#  :config
	#   A hash of return address details, often the output of Utils.whoami?
	class ARPPacket < Packet

		attr_accessor :eth_header, :arp_header

		def initialize(args={})
			@eth_header = EthHeader.new.read(args[:eth])
			@arp_header = ARPHeader.new.read(args[:arp])
			@eth_header.eth_proto = "\x08\x06"
			@eth_header.body=@arp_header

			# Please send more flavors to todb-packetfu@planb-security.net.
			# Most of these initial fingerprints come from one (1) sample.
			case (args[:flavor].nil?) ? :nil : args[:flavor].to_s.downcase.intern
			when :windows; @arp_header.body = "\x00" * 64				# 64 bytes of padding 
			when :linux; @arp_header.body = "\x00" * 4 +				# 32 bytes of padding 
				"\x00\x07\x5c\x14" + "\x00" * 4 +
				"\x00\x0f\x83\x34" + "\x00\x0f\x83\x74" +
				"\x01\x11\x83\x78" + "\x00\x00\x00\x0c" + 
				"\x00\x00\x00\x00"
			when :hp_deskjet; 																	# Pads up to 60 bytes.
				@arp_header.body = "\xe0\x90\x0d\x6c" + 
				"\xff\xff\xee\xee" + "\x00" * 4 + 
				"\xe0\x8f\xfa\x18\x00\x20"	
			else; @arp_header.body = "\x00" * 18								# Pads up to 60 bytes.
			end

			@headers = [@eth_header, @arp_header]
			super

		end

		# Used to generate summary data for ARP packets.
		def peek(args={})
			peek_data = ["A "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << arp_saddr_mac
			peek_data << "(#{arp_saddr_ip})"
			peek_data << "->"
			peek_data << case arp_daddr_mac
										when "00:00:00:00:00:00"; "Bcast00"
										when "ff:ff:ff:ff:ff:ff"; "BcastFF"
										else; arp_daddr_mac
										end
			peek_data << "(#{arp_daddr_ip})"
			peek_data << ":"
			peek_data << case arp_opcode
										when 1; "Requ"
										when 2; "Repl"
										when 3; "RReq"
										when 4; "RRpl"
										when 5; "IReq"
										when 6; "IRpl"
										else; "0x%02x" % arp_opcode
										end
			peek_data.join
		end

		# While there are lengths in ARPPackets, there's not
		# much to do with them.
		def recalc(args={})
			@headers[0].inspect
		end

	end # class ARPPacket

end # module PacketFu

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
