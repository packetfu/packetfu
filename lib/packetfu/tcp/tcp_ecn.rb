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

		def initialize(args={})
			super(args[:n], args[:c], args[:e])
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

end
