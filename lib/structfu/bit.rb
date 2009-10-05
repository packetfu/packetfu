module StructFu

	# Bit subclasses are intended to fill values to a specific
	# bit width. While to_s methods are provided, they are often
	# not useful.
	class Bit < Struct.new(:value, :width, :default)
		alias :v= :value=
		alias :v :value
		alias :w= :width=
		alias :w :width
		alias :d= :default=
		alias :d :default
		# This is a parent class definition and should not be used directly.
		def to_s
			raise StandardError, "StructFu::Int#to_s accessed, must be redefined."
		end
		def to_i
			(self.v || self.d).to_i
		end
		def to_f
			(self.v || self.d).to_f
		end
	end

	class Bit1 < Bit
		def initialize(v=nil, w=1, d=0)
			super
		end
		def to_s
			[((self.v || self.d) & 0b00000001)].pack("C")
		end
	end

	class Bit2 < Bit
		def initialize(v=nil, w=1, d=0)
			super
		end
		def to_s
			[((self.v || self.d) & 0b00000011)].pack("C")
		end
	end

	class Bit3 < Bit
		def initialize(v=nil, w=1, d=0)
			super
		end
		def to_s
			[((self.v || self.d) & 0b00000111)].pack("C")
		end
	end

	class Bit4 < Bit
		def initialize(v=nil, w=1, d=0)
			super
		end
		def to_s
			[((self.v || self.d) & 0b00001111)].pack("C")
		end
	end

	class Bit5 < Bit
		def initialize(v=nil, w=1, d=0)
			super
		end
		def to_s
			[((self.v || self.d) & 0b00011111)].pack("C")
		end
	end

	class Bit6 < Bit
		def initialize(v=nil, w=1, d=0)
			super
		end
		def to_s
			[((self.v || self.d) & 0b00111111)].pack("C")
		end
	end

	class Bit7 < Bit
		def initialize(v=nil, w=1, d=0)
			super
		end
		def to_s
			[((self.v || self.d) & 0b01111111)].pack("C")
		end
	end

	class Bit8 < Bit
		def initialize(v=nil, w=1, d=0)
			super
		end
		def to_s
			[self.v || self.d].pack("C")
		end
	end

end
