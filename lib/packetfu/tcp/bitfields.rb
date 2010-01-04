module PacketFu

	# Implements the Explict Congestion Notification for TCPHeader.
	#
	# ==== Header Definition
	#
	#
	#  bit1  :n
	#  bit1  :c
	#  bit1  :e
	class TcpEcn < Struct.new(:n, :c, :e)

		include StructFu

		def initialize(args={})
			super(args[:n], args[:c], args[:e]) if args
		end

		# Returns the TcpEcn field as an integer... even though it's going
		# to be split across a byte boundary.
		def to_i
			(n.to_i << 2) + (c.to_i << 1) + e.to_i
		end

		def read(str)
			return self if str.nil? || str.size < 2
			byte1 = str[0]
			byte2 = str[1]
			self[:n] = byte1 & 0b00000001 == 0b00000001 ? 1 : 0
			self[:c] = byte2 & 0b10000000 == 0b10000000 ? 1 : 0
			self[:e] = byte2 & 0b01000000 == 0b01000000 ? 1 : 0
			self
		end

	end

	class TcpHlen < Struct.new(:hlen)
		
		include StructFu

		def initialize(args={})
			super(args[:hlen])
		end

		# Returns the TcpHlen field as an integer. Note these will become the high
		# bits at the TCP header's offset, even though the lower 4 bits
		# will be further chopped up.
		def to_i
			hlen.to_i & 0b1111
		end

		def read(str)
			return self if str.nil? || str.size.zero?
			self[:hlen] = (str[0] & 0b11110000) >> 4
			self
		end

		def to_s
			[self.to_i].pack("C")
		end

	end

	# Implements the Reserved bits for TCPHeader.
	#
	# ==== Header Definition
	#
	#
	#  bit1  :r1
	#  bit1  :r2
	#  bit1  :r3
	class TcpReserved < Struct.new(:r1, :r2, :r3)

		include StructFu

		def initialize(args={})
			super(
				args[:r1] || 0,
				args[:r2] || 0,
				args[:r3] || 0) if args
		end

		# Returns the Reserved field as an integer.
		def to_i
			(r1.to_i << 2) + (r2.to_i << 1) + r3.to_i
		end

		def read(str)
			return self if str.nil? || str.size.zero?
			byte = str[0]
			self[:r1] = byte & 0b00000100 == 0b00000100 ? 1 : 0
			self[:r2] = byte & 0b00000010 == 0b00000010 ? 1 : 0
			self[:r3] = byte & 0b00000001 == 0b00000001 ? 1 : 0
			self
		end

	end

	# Implements flags for TCPHeader.
	#
	# ==== Header Definition
	#
	#  bit1  :urg
	#  bit1  :ack
	#  bit1  :psh
	#  bit1  :rst
	#  bit1  :syn
	#  bit1  :fin
	class TcpFlags < Struct.new(:urg, :ack, :psh, :rst, :syn, :fin)

		include StructFu

		def initialize(args={})
			# This technique attemts to ensure that flags are always 0 (off)
			# or 1 (on). Statements like nil and false shouldn't be lurking in here.
			if args.nil? || args.size.zero?
				super( 0, 0, 0, 0, 0, 0)
			else
				super(
					(args[:urg] ? 1 : 0), 
					(args[:ack] ? 1 : 0), 
					(args[:psh] ? 1 : 0), 
					(args[:rst] ? 1 : 0), 
					(args[:syn] ? 1 : 0), 
					(args[:fin] ? 1 : 0)
				)
			end
		end

		# Returns the TcpFlags as an integer.
		# Also not a great candidate for to_s due to the short bitspace.
		def to_i
			(urg.to_i << 5) + (ack.to_i << 4) + (psh.to_i << 3) + 
			(rst.to_i << 2) + (syn.to_i << 1) + fin.to_i
		end

		def zero_or_one(i=0)
			if i == 0 || i == false || i == nil
				0
			else
				1
			end
		end

		def urg=(i); self[:urg] = zero_or_one(i); end
		def ack=(i); self[:ack] = zero_or_one(i); end
		def psh=(i); self[:psh] = zero_or_one(i); end
		def rst=(i); self[:rst] = zero_or_one(i); end
		def syn=(i); self[:syn] = zero_or_one(i); end
		def fin=(i); self[:fin] = zero_or_one(i); end

		def read(str)
			return self if str.nil?
			byte = str[0]
			self[:urg] = byte & 0b00100000 == 0b00100000 ? 1 : 0
			self[:ack] = byte & 0b00010000 == 0b00010000 ? 1 : 0
			self[:psh] = byte & 0b00001000 == 0b00001000 ? 1 : 0
			self[:rst] = byte & 0b00000100 == 0b00000100 ? 1 : 0
			self[:syn] = byte & 0b00000010 == 0b00000010 ? 1 : 0
			self[:fin] = byte & 0b00000001 == 0b00000001 ? 1 : 0
			self
		end

	end

end
