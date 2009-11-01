module PacketFu

	# Packet is the parent class of EthPacket, IPPacket, UDPPacket, TCPPacket, and all
	# other packets.
	class Packet
		attr_reader :flavor # Packet Headers are responsible for their own specific flavor methods.
		attr_accessor :headers # All packets have a header collection, useful for determining protocol trees.

		# Parse() creates the correct packet type based on the data, and returns the apporpiate
		# Packet subclass. 
		#
		# There is an assumption here that all incoming packets are either EthPacket
		# or InvalidPacket types.
		#
		# New packet types should get an entry here. 
		def self.parse(packet,args={})
			if packet.size >= 14													# Min size for Ethernet. No check for max size, yet.
				case packet[12,2]														# Check the Eth protocol field.
				when "\x08\x00"															# It's IP.
					case (packet[14,1][0] >> 4)								# Check the IP version field.
					when 4;				 														# It's IPv4.
						case packet[23,1]												# Check the IP protocol field.
						when "\x06"; p = TCPPacket.new					# Returns a TCPPacket.
						when "\x11"; p = UDPPacket.new					# Returns a UDPPacket.
						when "\x01"; p = ICMPPacket.new					# Returns an ICMPPacket.
						else; p = IPPacket.new									# Returns an IPPacket since we can't tell the transport layer.
						end
					else; p = IPPacket.new										# Returns an EthPacket since we don't know any other IP version.
					end
				when "\x08\x06"															# It's arp
					if packet.size >= 28											# Min size for complete arp
						p = ARPPacket.new
					else; p = EthPacket.new										# Returns an EthPacket since we can't deal with tiny arps.
					end
				when "\x86\xdd"															# It's IPv6
					if packet.size >= 54											# Min size for a complete IPv6 packet.
						p = IPv6Packet.new
					else; p = EthPacket.new										# Returns an EthPacket since we can't deal with tiny Ipv6.
					end
				else; p = EthPacket.new											# Returns an EthPacket since we can't tell the network layer.
				end
			else
				p = InvalidPacket.new												# Not the right size for Ethernet (jumbo frames are okay)
			end
			parsed_packet = p.read(packet,args)
			return parsed_packet
		end

		#method_missing() delegates protocol-specific field actions to the apporpraite
		#class variable (which contains the associated packet type)
		#This register-of-protocols style switch will work for the 
		#forseeable future (there aren't /that/ many packet types), and it's a handy
		#way to know at a glance what packet types are supported.
		def method_missing(sym, *args)
			case sym.to_s
			when /^invalid_/
				@invalid_header.send(sym,*args)
			when /^eth_/
				@eth_header.send(sym,*args)
			when /^arp_/
				@arp_header.send(sym,*args)
			when /^ip_/
				@ip_header.send(sym,*args)
			when /^icmp_/
				@icmp_header.send(sym,*args)
			when /^udp_/
				@udp_header.send(sym,*args)
			when /^tcp_/
				@tcp_header.send(sym,*args)
			when /^ipv6_/
				@ipv6_header.send(sym,*args)
			else
				raise NoMethodError, "Unknown method `#{sym}' for this packet object."
			end
		end

		# Get the binary string of the entire packet.
		def to_s
			@headers[0].to_s
		end

		# In the event of no proper decoding, at least send it to the inner-most header.
		def read(io)
			@headers[0].read(io)
		end

		# In the event of no proper decoding, at least send it to the inner-most header.
		def write(io)
			@headers[0].write(io)
		end

		# Get the outermost payload (body) of the packet; this is why all packet headers
		# should have a body type.
		def payload
			@headers.last.body
		end

		# Set the outermost payload (body) of the packet.
		def payload=(args)
			@headers.last.body=(args)
		end

		# Put the entire packet into a libpcap file.
		def to_f(filename=nil)
			PacketFu::Write.a2f(:file=> filename || PacketFu::Config.new.config[:pcapfile],
													:arr=>[@headers[0].to_s])
		end

		# Put the entire packet on the wire by creating a temporary PacketFu::Inject object.
		# TODO: Do something with auto-checksumming?
		def to_w(iface=nil)
			inj = PacketFu::Inject.new(:iface => (iface || PacketFu::Config.new.config[:iface]))
			inj.array = [@headers[0].to_s]
			inj.inject
		end
		
		# Recalculates all the calcuated fields for all headers in the packet.
		# This is important since read() wipes out all the calculated fields
		# such as length and checksum and what all.
		# TODO: Is there a better way to ensure I get the correct checksum?
		# This way is pretty easy; third time is, indeed, the charm.
		def recalc(arg=:all)
			3.times do # XXX: This is a silly fix, surely there's a better way.
				case arg
				when :ip
					ip_recalc(:all)
				when :udp
					udp_recalc(:all)
				when :tcp
					tcp_recalc(:all)
				when :all
					ip_recalc(:all) if @ip_header
					udp_recalc(:all) if @udp_header
					tcp_recalc(:all) if @tcp_header
				else
					raise ArgumentError, "Recalculating `#{arg}' unsupported. Try :all"
				end
			end
			@headers[0]
		end

		# Read() takes (and trusts) the io input and shoves it all into a well-formed Packet.
		# Note that read is a destructive process, so any existing data will be lost.
		#
		# TODO: This giant if tree is a mess, and worse, is decieving. You need to define
		# actions both here and in parse(). All read() does is make a (good) guess as to
		# what @headers to expect, and reads data to them.
		#
		# To take strings and turn them into packets without knowing ahead of time what kind of
		# packet it is, use Packet.parse instead; parse() handles the figuring-out part.
		#
		# A note on the :strip => true argument: If :strip is set, defined lengths of data will
		# be believed, and any trailers (such as frame check sequences) will be chopped off. This
		# helps to ensure well-formed packets, at the cost of losing perhaps important FCS data.
		# 
		# If :strip is false, header lengths are /not/ believed, and all data will be piped in.
		# When capturing from the wire, this is usually fine, but recalculating the length before
		# saving or re-transmitting will absolutely change the data payload; FCS data will become
		# part of the TCP data as far as tcp_len is concerned. Some effort has been made to preserve
		# the "real" payload for the purposes of checksums, but currently, it's impossible to seperate
		# new payload data from old trailers, so things like pkt.payload += "some data" will not work
		# correctly.
		#
		# So, to summarize; if you intend to alter the data, use :strip. If you don't, don't. Also,
		# this is a horrid XXX hack. Stripping is useful (and fun!), but the default behavior really
		# should be to create payloads correctly, and /not/ treat extra FCS data as a payload.
		def read(io,args={})
			begin
				if io.size >= 14
					@eth_header.read(io[0,14])
					eth_proto_num = io[12,2].unpack("n")[0]
					if eth_proto_num == 0x0800 # It's IP.
						ip_hlen=(io[14] & 0x0f) * 4
						ip_ver=(io[14] >> 4) # It's IPv4. Other versions, all bets are off!
						if ip_ver == 4
							ip_proto_num = io[23,1].unpack("C")[0]
							@ip_header.read(io[14,ip_hlen])
							if ip_proto_num == 0x06 # It's TCP.
								tcp_len = io[16,2].unpack("n")[0] - 20
								if args[:strip] # Drops trailers like frame check sequence (FCS). Often desired for cleaner packets.
									tcp_all = io[ip_hlen+14,tcp_len] # Believe the tcp_len value; chop off anything that's not in range.
								else
									tcp_all = io[ip_hlen+14,0xffff] # Don't believe the tcp_len value; suck everything up.
								end
								tcp_hlen =  ((tcp_all[12,1].unpack("C")[0]) >> 4) * 4
								if tcp_hlen.to_i >= 20
									tcp_opts = tcp_all[20,tcp_hlen-20]
									tcp_body = tcp_all[tcp_hlen,0xffff]
									@tcp_header.read(tcp_all[0,20])
									@tcp_header.tcp_opts=tcp_opts
									@tcp_header.body=tcp_body
									@ip_header.body = @tcp_header
								else # It's a TCP packet with an impossibly small hlen, so it can't be real TCP. Abort! Abort!
									@ip_header.body = io[16,io.size-16]
								end
								tcp_opts = tcp_all[20,tcp_hlen-20]
								tcp_body = tcp_all[tcp_hlen,0xffff]
								@tcp_header.read(tcp_all[0,20])
								@tcp_header.tcp_opts=tcp_opts
								@tcp_header.body=tcp_body
								@ip_header.body = @tcp_header
							elsif ip_proto_num == 0x11 # It's UDP.
								udp_len = io[16,2].unpack("n")[0] - 20
								if args[:strip] # Same deal as with TCP. We might have stuff at the end of the packet that's not part of the payload.
									@udp_header.read(io[ip_hlen+14,udp_len]) 
								else # ... Suck it all up. BTW, this will change the lengths if they are ever recalc'ed. Bummer.
									@udp_header.read(io[ip_hlen+14,0xffff])
								end
								@ip_header.body = @udp_header
							elsif ip_proto_num == 1 # It's ICMP
								@icmp_header.read(io[ip_hlen+14,0xffff])
								@ip_header.body = @icmp_header
							else # It's an IP packet for a protocol we don't have a decoder for.
								@ip_header.body = io[16,io.size-16] 
							end
						else # It's not IPv4, so no idea what should come next. Just dump it all into an ip_header and ip payload.
							@ip_header.read(io[14,ip_hlen])
							@ip_header.body = io[16,io.size-16]
						end
						@eth_header.body = @ip_header
					elsif eth_proto_num == 0x0806 # It's ARP
						@arp_header.read(io[14,0xffff]) # You'll nearly have a trailer and you'll never know what size.
						@eth_header.body=@arp_header
					elsif eth_proto_num == 0x86dd # It's IPv6
						@ipv6_header.read(io[14,0xffff])
						@eth_header.body=@ipv6_header
					else # It's an Ethernet packet for a protocol we don't have a decoder for
						@eth_header.body = io[14,io.size-14]
					end
					if (args[:fix] || args[:recalc])
						# Unfortunately, we cannot simply recalc with abandon, since
						# we may have unaccounted trailers that will sneak into the checksum.
						# The better way to handle this is to put trailers in their own
						# StructFu field, but I'm not a-gonna right now. :/
						ip_recalc(:ip_sum) if respond_to? :ip_header
						recalc(:tcp) if respond_to? :tcp_header
						recalc(:udp) if respond_to? :udp_header
					end
				else # You're not big enough for Ethernet. 
					@invalid_header.read(io)
				end	
				# @headers[0]
				self
			rescue ::Exception => e
				# remove last header
				# nested_types = self.headers.collect {|header| header.class}
				# nested_types.pop # whatever this packet type is, we weren't able to parse it
				self.headers.pop
				return_header_type = self.headers[self.headers.length-1].class.to_s
				retklass = PacketFu::InvalidPacket
				seekpos = 0
				target_header = @invalid_header
				case return_header_type.to_s
				when "PacketFu::EthHeader"
					retklass = PacketFu::EthPacket
					seekpos = 0x0e
					target_header = @eth_header
				when "PacketFu::IPHeader"
					retklass = PacketFu::IPPacket
					seekpos = 0x0e + @ip_header.ip_hl * 4
					target_header = @ip_header
				when "PacketFu::TCPHeader"
					retklass = PacketFu::TCPPacket
					seekpos = 0x0e + @ip_header.ip_hl * 4 + @tcpheader.tcp_hlen
					target_header = @tcp_header
				when "PacketFu::UDPHeader"
					retklass = PacketFu::UDPPacket
				when "PacketFu::ARPHeader"
					retklass = PacketFu::ARPPacket
				when "PacketFu::ICMPHeader"
					retklass = PacketFu::ICMPPacket
				when "PacketFu::IPv6Header"
					retklass = PacketFu::IPv6Packet
				else
				end
			
				io = io[seekpos,io.length - seekpos]
				target_header.body = io
				p = retklass.new
				p.headers = self.headers
				p
			end
		end

		# Peek provides summary data on packet contents.
		# Each packet type should provide its own peek method, and shouldn't exceed 80 characters wide (for
		# easy reading in normal irb shells). If they don't, this default summary will step in.
		def peek(args={})
			peek_data = ["? "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%68s" % self.to_s[0,34].unpack("H*")[0]
			peek_data.join
		end

		# Hexify provides a neatly-formatted dump of binary data, familar to hex readers.
		def hexify(str)
			hexascii_lines = str.to_s.unpack("H*")[0].scan(/.{1,32}/)
			chars = str.to_s.gsub(/[\x00-\x1f\x7f-\xff]/,'.')
			chars_lines = chars.scan(/.{1,16}/)
			ret = []
			hexascii_lines.size.times {|i| ret << "%-48s  %s" % [hexascii_lines[i].gsub(/(.{2})/,"\\1 "),chars_lines[i]]}
			ret.join("\n")
		end

		# Returns a hex-formatted representation of the packet.
		#
		# ==== Arguments
		#
		# 0..9 : If a number is given only the layer in @header[arg] will be displayed. Note that this will include all @headers included in that header.
		# :layers : If :layers is specified, the dump will return an array of headers by layer level.
		# :all : An alias for arg=0.
		#
		# ==== Examples
		#
		#   irb(main):003:0> pkt = TCPPacket.new
		#   irb(main):003:0> puts pkt.inspect_hex(:layers)
		#   00 1a c5 00 00 00 00 1a c5 00 00 00 08 00 45 00   ..............E.
		#   00 28 83 ce 00 00 ff 06 38 02 00 00 00 00 00 00   .(......8.......
		#   00 00 a6 0f 00 00 ac 89 7b 26 00 00 00 00 50 00   ........{&....P.
		#   40 00 a2 25 00 00                                 @..%..
		#   45 00 00 28 83 ce 00 00 ff 06 38 02 00 00 00 00   E..(......8.....
		#   00 00 00 00 a6 0f 00 00 ac 89 7b 26 00 00 00 00   ..........{&....
		#   50 00 40 00 a2 25 00 00                           P.@..%..
		#   a6 0f 00 00 ac 89 7b 26 00 00 00 00 50 00 40 00   ......{&....P.@.
		#   a2 25 00 00                                       .%..
		#   => nil
		#   irb(main):004:0> puts pkt.inspect_hex(:layers)[2]
		#   a6 0f 00 00 ac 89 7b 26 00 00 00 00 50 00 40 00   ......{&....P.@.
		#   a2 25 00 00                                       .%..
		#   => nil
		#
		def inspect_hex(arg=0)
			case arg
			when :layers
				ret = []
				@headers.size.times do |i|
					ret << hexify(@headers[i])
				end
				ret
			when (0..9)
				if @headers[arg]
					hexify(@headers[arg])
				else
					nil
				end
			when :all
				inspect_hex(0)
			end
		end

		# For packets, inspect is overloaded as inspect_hex(0).
		# Not sure if this is a great idea yet, but it sure makes
		# the irb output more sane. Fix this with PacketFu.toggle_inspect
		def inspect
			self.proto.join("|") + "\n" + self.inspect_hex
		end

		# Returns the size of the packet (as a binary string)
		def size
			self.to_s.size
		end

		# Returns an array of protocols contained in this packet. For example:
		#
		#   t = PacketFu::TCPPacket.new
		#   => 00 1a c5 00 00 00 00 1a c5 00 00 00 08 00 45 00   ..............E.
		#   00 28 3c ab 00 00 ff 06 7f 25 00 00 00 00 00 00   .(<......%......
		#   00 00 93 5e 00 00 ad 4f e4 a4 00 00 00 00 50 00   ...^...O......P.
		#   40 00 4a 92 00 00                                 @.J...
		#   t.proto
		#   => ["Eth", "IP", "TCP"]
		#
		def proto
			type_array = []
			self.headers.each {|header| type_array << header.class.to_s.split('::').last.gsub(/Header$/,'')}
			type_array
		end

		alias_method :protocol, :proto

		# Returns true if this is an Invalid packet. Else, false.
		def is_invalid? ;	self.proto.include? "Invalid"; end

		# Returns true if this is an Ethernet packet. Else, false.
		def is_eth? ;	self.proto.include? "Eth"; end
		alias_method :is_ethernet?, :is_eth?

		# Returns true if this is an IP packet. Else, false.
		def is_ip? ;	self.proto.include? "IP"; end
		# Returns true if this is an TCP packet. Else, false.
		def is_tcp? ;	self.proto.include? "TCP"; end
		# Returns true if this is an UDP packet. Else, false.
		def is_udp? ;	self.proto.include? "UDP"; end
		# Returns true if this is an ARP packet. Else, false.
		def is_arp? ; self.proto.include? "ARP"; end
		# Returns true if this is an IPv6 packet. Else, false.
		def is_ipv6? ; self.proto.include? "IPv6" ; end
		# Returns true if this is an ICMP packet. Else, false.
		def is_icmp? ; self.proto.include? "ICMP" ; end
		# Returns true if the outermost layer has data. Else, false.
		def has_data? ; self.payload.size.zero? ? false : true ; end

		alias_method :length, :size

		def initialize(args={})
			if args[:config]
				args[:config].each_pair do |k,v|
					case k
					when :eth_daddr; @eth_header.eth_daddr=v if @eth_header
					when :eth_saddr; @eth_header.eth_saddr=v if @eth_header
					when :ip_saddr; @ip_header.ip_saddr=v		 if @ip_header
					end
				end
			end
		end

	end # class Packet

	@@inspect_style = :pretty

	# If @@inspect_style is :ugly, set the inspect method to the usual inspect. 
	# By default, @@inspect_style is :pretty. This default may change if people
	# hate it.
	# Since PacketFu is designed with irb in mind, the normal inspect is way too
	# verbose when new packets are created, and it ruins the aesthetics of the
	# PacketFu console or quick hping-like exercises in irb.
	#
	# However, there are cases where knowing things like object id numbers, the complete
	# @header array, etc. is useful (especially in debugging). So, toggle_inspect
	# provides a means for a script to declar which style of inspect to use.
	# 
	# This method may be an even worse idea than the original monkeypatch to Packet.inspect,
	# since it would almost certainly be better to redefine inspect just in the PacketFu console.
	# We'll see what happens.
	#
	# == Example
	#
	#  irb(main):001:0> p = PacketFu::TCPPacket.new
	#  => Eth|IP|TCP
	#  00 1a c5 00 00 00 00 1a c5 00 00 00 08 00 45 00   ..............E.
	#  00 28 ea d7 00 00 ff 06 d0 f8 00 00 00 00 00 00   .(..............
	#  00 00 a9 76 00 00 f9 28 7e 95 00 00 00 00 50 00   ...v...(~.....P.
	#  40 00 4e b0 00 00                                 @.N...
	#  irb(main):002:0> PacketFu.toggle_inspect
	#  => :ugly
	#  irb(main):003:0> p = PacketFu::TCPPacket.new
	#  => #<PacketFu::TCPPacket:0xb7acfd84 @headers=[{"eth_src"=>{"oui"=>{"local"=
	#  >0, "oui"=>6853, "b0"=>0, "b1"=>0, "b2"=>0, "multicast"=>0, "b3"=>0, "b4"=>
	#  0, "b5"=>0}, "nic"=>{"n1"=>0, "n2"=>0, "n3"=>0}}, "body"=>{"ip_tos"=>0, "ip
	#  _src"=>{"o1"=>0, "o2"=>0, "o3"=>0, "o4"=>0}, "body"=>{"tcp_ecn"=>{"c"=>0, "
	#  n"=>0, "e"=>0}, "tcp_dst"=>0, "tcp_win"=>16384, "body"=>"", "tcp_flags"=>{"
	#  fin"=>0, "psh"=>0, "syn"=>0, "rst"=>0, "ack"=>0, "urg"=>0}, "tcp_hlen"=>5, 
	#  "tcp_ack"=>0, "tcp_urg"=>0, "tcp_seq"=>1579966596, "tcp_sum"=>311, "tcp_res
	#  erved"=>0, "tcp_opts"=>"", "tcp_src"=>45053}, "ip_dst"=>{"o1"=>0, "o2"=>0, 
	#  "o3"=>0, "o4"=>0}, "ip_frag"=>0, "ip_proto"=>6, "ip_hl"=>5, "ip_len"=>40, "
	#  ip_sum"=>44782, "ip_id"=>3298, "ip_v"=>4, "ip_ttl"=>255}, "eth_proto"=>2048
	#  , "eth_dst"=>{"oui"=>{"local"=>0, "oui"=>6853, "b0"=>0, "b1"=>0, "b2"=>0, "
	#  multicast"=>0, "b3"=>0, "b4"=>0, "b5"=>0}, "nic"=>{"n1"=>0, "n2"=>0, "n3"=>
	#  0}}}, {"ip_tos"=>0, "ip_src"=>{"o1"=>0, "o2"=>0, "o3"=>0, "o4"=>0}, "body"=
	#  >{"tcp_ecn"=>{"c"=>0, "n"=>0, "e"=>0}, "tcp_dst"=>0, "tcp_win"=>16384, "bod
	#  y"=>"", "tcp_flags"=>{"fin"=>0, "psh"=>0, "syn"=>0, "rst"=>0, "ack"=>0, "ur
	#  g"=>0}, "tcp_hlen"=>5, "tcp_ack"=>0, "tcp_urg"=>0, "tcp_seq"=>1579966596, "
	#  [...etc...]
	#  irb(main):004:0> 
	def toggle_inspect
		if @@inspect_style == :pretty
			eval("class Packet; def inspect; super; end; end")
			@@inspect_style = :ugly
		else
			eval("class Packet; def inspect; self.proto.join('|') + \"\n\" + self.inspect_hex; end; end")
			@@inspect_style = :pretty
		end
	end

end # module PacketFu
