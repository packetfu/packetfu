require 'packetfu/lib/tcpopts'
module PacketFu

	# Implements the Explict Congestion Notification for TCPHeader.
	class TcpEcn < BinData::MultiValue
		bit1	:n
		bit1	:c
		bit1	:e

		# Returns the TcpEcn field as an integer.
		def to_i
			(n << 2) + (c << 1) + e
		end
	end

	# Implements flags for TCPHeader.
	class TcpFlags < BinData::MultiValue
		bit1	:urg
		bit1	:ack
		bit1	:psh
		bit1	:rst
		bit1	:syn
		bit1	:fin

		# Returns the TcpFlags as an integer.
		def to_i
			(urg << 5) + (ack << 4) + (psh << 3) + (rst << 2) + (syn << 1) + fin
		end
	end

	# TCPHeader is a complete TCP struct, used in TCPPacket. Most IP traffic is TCP-based, by
	# volume.
	#
	# For more on TCP packets, see http://www.networksorcery.com/enp/protocol/tcp.htm
	class TCPHeader < BinData::MultiValue
		uint16be	:tcp_src
		uint16be	:tcp_dst
		uint32be	:tcp_seq
		uint32be	:tcp_ack
		bit4			:tcp_hlen,	:initial_value => 5 # Must recalc as options are set. 
		bit3			:tcp_reserved
		tcp_ecn		:tcp_ecn
		tcp_flags	:tcp_flags
		uint16be	:tcp_win
		uint16be	:tcp_sum, 	:initial_value =>	0 # Must set this upon generation.
		uint16be	:tcp_urg
		string		:tcp_opts
		rest			:body

		# tcp_calc_hlen adjusts the header length to account for tcp_opts. Note
		# that if tcp_opts does not fall on a 32-bit boundry, tcp_calc_hlen will
		# additionally pad the option string with nulls. Most stacks avoid this 
		# eventuality by padding with NOP options at OS-specific points in the 
		# option field. The practical effect of this is, you should tcp_calc_hlen
		# only when all the options are already set; otherwise, additional options
		# will be lost to the reciever as \x00 is an EOL option. Additionally,
		# (and this is almost certainly a bug), there is no sanity checking to
		# ensure the final tcp_opts value is 44 bytes or less (any more will bleed
		# over into the tcp payload). You are forewarned!
		#
		# If you would like to craft specifically malformed packets with 
		# nonsense lengths of opts fields, you should avoid tcp_calc_hlen 
		# altogether, and simply set the values for tcp_hlen and tcp_opts manually.
		def tcp_calc_hlen
			pad = (self.tcp_opts.to_s.size % 4)
			if (pad > 0)
				self.tcp_opts += ("\x00" * pad)
			end
			self.tcp_hlen = ((20 + self.tcp_opts.to_s.size) / 4)
		end

		# Returns the actual length of the TCP options.
		def tcp_opts_len
			tcp_opts.to_s.size * 4
		end

		# Returns a more readable option list. Note, it can lack fidelity on bad option strings.
		# For more on TCP options, see the TcpOpts class.
		def tcp_options
			TcpOpts.decode(self.tcp_opts)
		end

		# Allows a more writable version of TCP options. 
		# For more on TCP options, see the TcpOpts class.
		def tcp_options=(arg)
			self.tcp_opts=TcpOpts.encode(arg) 
		end

		# Recalculates calculated fields for TCP.
		def tcp_recalc(arg=:all)
			case arg
			when :tcp_hlen
				tcp_calc_hlen
			when :all
				tcp_calc_hlen
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

	end

	# TCPPacket is used to construct TCP packets. They contain an EthHeader, an IPHeader, and a TCPHeader.
	#
	# == Example
	#
  #    tcp_pkt = PacketFu::TCPPacket.new
  #    tcp_pkt.tcp_flags.syn=1
  #    tcp_pkt.tcp_src=rand(0xffff-1024) + 1024
  #    tcp_pkt.tcp_dst=80
  #    tcp_pkt.tcp_win=5840
  #    tcp_pkt.tcp_options="mss:1460,sack.ok,ts:#{rand(0xffffffff)};0,nop,ws:7"
	#
  #    tcp_pkt.ip_saddr=[rand(0xff),rand(0xff),rand(0xff),rand(0xff)].join('.')
  #    tcp_pkt.ip_daddr=[rand(0xff),rand(0xff),rand(0xff),rand(0xff)].join('.')
	#
  #    tcp_pkt.recalc
  #    tcp_pkt.to_f('/tmp/tcp.pcap')
	#  
	#
	# == Parameters
	#  :eth
	#    A pre-generated EthHeader object.
	#  :ip
	#    A pre-generated IPHeader object.
	#  :flavor
	#    TODO: Sets the "flavor" of the TCP packet. This will include TCP options and the initial window
	#    size, per stack. There is a lot of variety here, and it's one of the most useful methods to
	#    remotely fingerprint devices. :flavor will span both ip and tcp for consistency.
	
	class TCPPacket < Packet

		attr_accessor :eth_header, :ip_header, :tcp_header, :headers
		attr_reader :size, :length
		
		def initialize(args={})
			@eth_header = 	(args[:eth] || EthHeader.new)
			@ip_header 	= 	(args[:ip]	|| IPHeader.new)
			@tcp_header = 	(args[:tcp] || TCPHeader.new)

			@ip_header.body = @tcp_header
			@eth_header.body = @ip_header
			@headers = [@eth_header, @ip_header, @tcp_header]

			@ip_header.ip_proto=0x06
			tcp_calc_sum
		end

		# tcp_calc_sum() computes the TCP checksum, and is called upon intialization. It usually
		# should be called just prior to dropping packets to a file or on the wire.
		def tcp_calc_sum
			# This is /not/ delegated down to @tcp_header since we need info
			# from the IP header, too.
			checksum =  (ip_src.to_i >> 16)
			checksum += (ip_src.to_i & 0xffff)
			checksum += (ip_dst.to_i >> 16)
			checksum += (ip_dst.to_i & 0xffff)
			checksum += 0x06 # TCP Protocol.
			checksum +=	(ip_len.to_i - ((ip_hl.to_i) * 4))
			checksum += tcp_src
			checksum += tcp_dst
			checksum += (tcp_seq.to_i >> 16)
			checksum += (tcp_seq.to_i & 0xffff)
			checksum += (tcp_ack.to_i >> 16)
			checksum += (tcp_ack.to_i & 0xffff)
			checksum += ((tcp_hlen << 12) + 
									 (tcp_reserved << 9) + 
									 (tcp_ecn.to_i << 6) + 
									 tcp_flags.to_i
									)
			checksum += tcp_win
			checksum += tcp_urg

			chk_tcp_opts = (tcp_opts.to_s.size % 2 == 0 ? tcp_opts.to_s : tcp_opts.to_s + "\x00") 
			chk_tcp_opts.scan(/[\x00-\xff]{2}/).collect { |x| (x[0] << 8) + x[1] }.each { |y| checksum += y}
			if (ip_len - ((ip_hl + tcp_hlen) * 4)) >= 0
				real_tcp_payload = payload[0,( ip_len - ((ip_hl + tcp_hlen) * 4) )] # Can't forget those pesky FCSes!
			else
				real_tcp_payload = payload # Something's amiss here so don't bother figuring out where the real payload is.
			end
			chk_payload = (real_tcp_payload.size % 2 == 0 ? real_tcp_payload : real_tcp_payload + "\x00") # Null pad if it's odd.
			chk_payload.scan(/[\x00-\xff]{2}/).collect { |x| (x[0] << 8) + x[1] }.each { |y| checksum += y}
			checksum = checksum % 0xffff
			checksum = 0xffff - checksum
			checksum == 0 ? 0xffff : checksum
			@tcp_header.tcp_sum = checksum
		end

		# tcp_recalc() recalculates various fields of the TCP packet. Valid arguments are:
		#
		#   :all
		#     Recomputes all calculated fields.
		#   :tcp_sum
		#     Recomputes the TCP checksum.
		#   :tcp_hlen
		#     Recomutes the TCP header length. Useful after options are added.
		def tcp_recalc(arg=:all)
			case arg
			when :tcp_sum
				tcp_calc_sum
			when :tcp_hlen
				@tcp_header.tcp_recalc :tcp_hlen
			when :all
				@tcp_header.tcp_recalc :all
				tcp_calc_sum
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

		# Peek provides summary data on packet contents.
		def peek(args={})
			peek_data = ["T "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%-21s" % "#{self.ip_saddr}:#{self.tcp_src}"
			peek_data << "->"
			peek_data << "%21s" % "#{self.ip_daddr}:#{self.tcp_dst}"
			flags = ' ['
			flags << (self.tcp_flags.urg.zero? ? "." : "U")
			flags << (self.tcp_flags.ack.zero? ? "." : "A")
			flags << (self.tcp_flags.psh.zero? ? "." : "P")
			flags << (self.tcp_flags.rst.zero? ? "." : "R")
			flags << (self.tcp_flags.syn.zero? ? "." : "S")
			flags << (self.tcp_flags.fin.zero? ? "." : "F")
			flags << '] '
			peek_data << flags
			peek_data << "S:"
			peek_data << "%08x" % self.tcp_seq
			peek_data << "|I:"
			peek_data << "%04x" % self.ip_id
			peek_data.join
		end

	end

end # module PacketFu

