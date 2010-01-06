$: << File.expand_path(File.dirname(__FILE__))
require 'tcp/bitfields'
require 'tcp/options'

module PacketFu

	# TCPHeader is a complete TCP struct, used in TCPPacket. Most IP traffic is TCP-based, by
	# volume.
	#
	# For more on TCP packets, see http://www.networksorcery.com/enp/protocol/tcp.htm
	#
	# ==== Header Definition
	# 
	#   uint16be  :tcp_src,  :initial_value => lambda {tcp_calc_src}
	#   uint16be  :tcp_dst
	#   uint32be  :tcp_seq,  :initial_value => lambda {tcp_calc_seq}
	#   uint32be  :tcp_ack
	#   bit4      :tcp_hlen, :initial_value => 5       # Must recalc as options are set. 
	#   bit3      :tcp_reserved
	#   tcp_ecn   :tcp_ecn
	#   tcp_flags :tcp_flags
	#   uint16be  :tcp_win,  :initial_value => 0x4000 # WinXP's default syn packet
	#   uint16be  :tcp_sum,  :initial_value => 0      # Must set this upon generation.
	#   uint16be  :tcp_urg
	#   string    :tcp_opts
	#   rest      :body
	#
	# See also TcpHlen, TcpReserved, TcpEcn, TcpFlags, TcpOpts
	class TCPHeader < Struct.new(:tcp_src, :tcp_dst,
															 :tcp_seq,
															 :tcp_ack,
															 :tcp_hlen, :tcp_reserved, :tcp_ecn, :tcp_flags, :tcp_win, 
															 :tcp_sum, :tcp_urg, 
															 :tcp_opts, :body)
		include StructFu

		def initialize(args={})
			@random_seq = rand(0xffffffff)
			@random_src = rand_port
			super(
				Int16.new(args[:tcp_src] || tcp_calc_src),
				Int16.new(args[:tcp_dst]),
				Int32.new(args[:tcp_seq] || tcp_calc_seq),
				Int32.new(args[:tcp_ack]),
				TcpHlen.new(:hlen => (args[:tcp_hlen] || 5)),
				TcpReserved.new(args[:tcp_reserved] || 0),
				TcpEcn.new(args[:tcp_ecn]),
				TcpFlags.new(args[:tcp_flags]),
				Int16.new(args[:tcp_win] || 0x4000),
				Int16.new(args[:tcp_sum] || 0),
				Int16.new(args[:tcp_urg]),
				TcpOptions.new.read(args[:tcp_opts]),
				StructFu::String.new.read(args[:body])
			)
		end

		attr_accessor :flavor

		def bits_to_s
			bytes = []
			bytes[0] = (self[:tcp_hlen].to_i << 4) +
				(self[:tcp_reserved].to_i << 1) +
				self[:tcp_ecn].n.to_i
			bytes[1] = (self[:tcp_ecn].c.to_i << 7) +
				(self[:tcp_ecn].e.to_i << 6) +
				self[:tcp_flags].to_i
			bytes.pack("CC")
		end

		def to_s
			hdr = self.to_a.map do |x|
				if x.kind_of? TcpHlen
					bits_to_s
				elsif x.kind_of? TcpReserved
					next
				elsif x.kind_of? TcpEcn
					next
				elsif x.kind_of? TcpFlags
					next
				else
					x.to_s
				end
			end
			hdr.flatten.join
		end

		def read(str)
			return self if str.nil?
			self[:tcp_src].read(str[0,2])
			self[:tcp_dst].read(str[2,2])
			self[:tcp_seq].read(str[4,4])
			self[:tcp_ack].read(str[8,4])
			self[:tcp_hlen].read(str[12,1])
			self[:tcp_reserved].read(str[12,1])
			self[:tcp_ecn].read(str[12,2])
			self[:tcp_flags].read(str[13,1])
			self[:tcp_win].read(str[14,2])
			self[:tcp_sum].read(str[16,2])
			self[:tcp_urg].read(str[18,2])
			self[:tcp_opts].read(str[20,((self[:tcp_hlen].to_i * 4) - 20)])
			self[:body].read(str[(self[:tcp_hlen].to_i * 4),str.size])
			self
		end

		def tcp_src=(i); typecast i; end
		def tcp_src; self[:tcp_src].to_i; end
		def tcp_dst=(i); typecast i; end
		def tcp_dst; self[:tcp_dst].to_i; end
		def tcp_seq=(i); typecast i; end
		def tcp_seq; self[:tcp_seq].to_i; end
		def tcp_ack=(i); typecast i; end
		def tcp_ack; self[:tcp_ack].to_i; end
		def tcp_win=(i); typecast i; end
		def tcp_win; self[:tcp_win].to_i; end
		def tcp_sum=(i); typecast i; end
		def tcp_sum; self[:tcp_sum].to_i; end
		def tcp_urg=(i); typecast i; end
		def tcp_urg; self[:tcp_urg].to_i; end

		def tcp_hlen; self[:tcp_hlen].to_i; end
		def tcp_hlen=(i)
			if i.kind_of? PacketFu::TcpHlen
				self[:tcp_hlen]=i
			else
				self[:tcp_hlen].read(i)
			end
		end

		def tcp_reserved; self[:tcp_reserved].to_i; end
		def tcp_reserved=(i)
			if i.kind_of? PacketFu::TcpReserved
				self[:tcp_reserved]=i
			else
				self[:tcp_reserved].read(i)
			end
		end

		def tcp_ecn; self[:tcp_ecn].to_i; end
		def tcp_ecn=(i)
			if i.kind_of? PacketFu::TcpEcn
				self[:tcp_ecn]=i
			else
				self[:tcp_ecn].read(i)
			end
		end

		def tcp_opts; self[:tcp_opts].to_s; end
		def tcp_opts=(i)
			if i.kind_of? PacketFu::TcpOptions
				self[:tcp_opts]=i
			else
				self[:tcp_opts].read(i)
			end
		end

		def tcp_calc_seq; @random_seq; end
		def tcp_calc_src; @random_src; end

		def tcp_opts_len
			self[:tcp_opts].to_s.size
		end

		# Sets and returns the true length of the TCP Header. 
		def tcp_calc_hlen
			tcp_hlen = (20 + tcp_opts_len) / 4
		end

		# Generates a random high port. This is affected by packet flavor.
		def rand_port
			rand(0xffff - 1025) + 1025
		end

		# Gets a more readable option list.
		def tcp_options
		 self[:tcp_opts].decode
		end

		# Sets a more readable option list.
		def tcp_options=(arg)
			self[:tcp_opts].encode arg
		end

		# Equivalent to tcp_src.
		def tcp_sport
			self.tcp_src.to_i
		end

		# Equivalent to tcp_src=.
		def tcp_sport=(arg)
			self.tcp_src=(arg)
		end

		# Equivalent to tcp_dst.
		def tcp_dport
			self.tcp_dst.to_i
		end
		
		# Equivalent to tcp_dst=.
		def tcp_dport=(arg)
			self.tcp_dst=(arg)
		end

		# Recalculates calculated fields for TCP (except checksum which is at the Packet level).
		def tcp_recalc(arg=:all)
			case arg
			when :tcp_hlen
				tcp_calc_hlen
			when :tcp_src
				@random_tcp_src = rand_port
			when :tcp_sport
				@random_tcp_src = rand_port
			when :tcp_seq
				@random_tcp_seq = rand(0xffffffff) 
			when :all
				tcp_calc_hlen
				@random_tcp_src = rand_port
				@random_tcp_seq = rand(0xffffffff) 
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
	# == Parameters
	#  :eth
	#    A pre-generated EthHeader object.
	#  :ip
	#    A pre-generated IPHeader object.
	#  :flavor
	#    TODO: Sets the "flavor" of the TCP packet. This will include TCP options and the initial window
	#    size, per stack. There is a lot of variety here, and it's one of the most useful methods to
	#    remotely fingerprint devices. :flavor will span both ip and tcp for consistency.
	#   :type
	#    TODO: Set up particular types of packets (syn, psh_ack, rst, etc). This can change the initial flavor.
	#  :config
	#   A hash of return address details, often the output of Utils.whoami?
	class TCPPacket < Packet

		attr_accessor :eth_header, :ip_header, :tcp_header, :headers
		
		def initialize(args={})
			@eth_header = 	(args[:eth] || EthHeader.new)
			@ip_header 	= 	(args[:ip]	|| IPHeader.new)
			@tcp_header = 	(args[:tcp] || TCPHeader.new)
			@tcp_header.flavor = args[:flavor].to_s.downcase

			@ip_header.body = @tcp_header
			@eth_header.body = @ip_header
			@headers = [@eth_header, @ip_header, @tcp_header]

			@ip_header.ip_proto=0x06
			super
			if args[:flavor]
				tcp_calc_flavor(@tcp_header.flavor)
			else
				tcp_calc_sum
			end
		end

		# Sets the correct flavor for TCP Packets. Recognized flavors are:
		#   windows, linux, freebsd
		def tcp_calc_flavor(str)
			ts_val = Time.now.to_i + rand(0x4fffffff)
			ts_sec = rand(0xffffff)
			case @tcp_header.flavor = str.to_s.downcase
			when "windows" # WinXP's default syn
				@tcp_header.tcp_win = 0x4000
				@tcp_header.tcp_options="MSS:1460,NOP,NOP,SACKOK"
				@tcp_header.tcp_src = rand(5000 - 1026) + 1026
				@ip_header.ip_ttl = 64
			when "linux" # Ubuntu Linux 2.6.24-19-generic default syn
				@tcp_header.tcp_win = 5840
				@tcp_header.tcp_options="MSS:1460,SACKOK,TS:#{ts_val};0,NOP,WS:7"
				@tcp_header.tcp_src = rand(61_000 - 32_000) + 32_000
				@ip_header.ip_ttl = 64
			when "freebsd" # Freebsd
				@tcp_header.tcp_win = 0xffff
				@tcp_header.tcp_options="MSS:1460,NOP,WS:3,NOP,NOP,TS:#{ts_val};#{ts_sec},SACKOK,EOL,EOL"
				@ip_header.ip_ttl = 64
			else
				@tcp_header.tcp_options="MSS:1460,NOP,NOP,SACKOK"
			end
			tcp_calc_sum
		end

		# tcp_calc_sum() computes the TCP checksum, and is called upon intialization. It usually
		# should be called just prior to dropping packets to a file or on the wire.
		#--
		# This is /not/ delegated down to @tcp_header since we need info
		# from the IP header, too.
		#++
		def tcp_calc_sum
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
			chk_tcp_opts.unpack("n*").each {|x| checksum = checksum + x }
			if (ip_len - ((ip_hl + tcp_hlen) * 4)) >= 0
				real_tcp_payload = payload[0,( ip_len - ((ip_hl + tcp_hlen) * 4) )] # Can't forget those pesky FCSes!
			else
				real_tcp_payload = payload # Something's amiss here so don't bother figuring out where the real payload is.
			end
			chk_payload = (real_tcp_payload.size % 2 == 0 ? real_tcp_payload : real_tcp_payload + "\x00") # Null pad if it's odd.
			chk_payload.unpack("n*").each {|x| checksum = checksum+x }
			checksum = checksum % 0xffff
			checksum = 0xffff - checksum
			checksum == 0 ? 0xffff : checksum
			@tcp_header.tcp_sum = checksum
		end

		# Recalculates various fields of the TCP packet.
		#
		# ==== Parameters
		#
		#   :all
		#     Recomputes all calculated fields.
		#   :tcp_sum
		#     Recomputes the TCP checksum.
		#   :tcp_hlen
		#     Recomputes the TCP header length. Useful after options are added.
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
