module StructFu

	# Ints all have a value, an endianness, and a default value.
	# Note that the signedness of Int values are implicit as
	# far as the subclasses are concerned; to_i and to_f will 
	# return Integer/Float versions of the input value, instead
	# of attempting to unpack the pack value. (This can be a useful
	# hint to other functions).
	class Int < Struct.new(:value, :endian, :width, :default)
		alias :v= :value=
		alias :v :value
		alias :e= :endian=
		alias :e :endian
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
		
		def initialize(value=nil, endian=nil, width=nil, default=nil)
			super(value,endian,width,default=0)
		end

		def read(str)
			self.v = str.unpack(@packstr).first
			self
		end

	end

	class Int8 < Int

		def initialize(v=nil)
			super(v,nil,w=1)
			@packstr = "C"
		end

		def to_s
		 [(self.v || self.d)].pack("C")
		end

		def read(str)
			self.v = str.unpack("C").first
			self
		end

	end

	class Int16 < Int
		def initialize(v=nil, e=:big)
			super(v,e,w=2)
			@packstr = (self.e == :big) ? "n" : "v"
		end

		def to_s
			[(self.v || self.d)].pack(@packstr)
	 	end

		def read(str)
			self.v = str.unpack(@packstr).first
			self
		end

	end

	class Int16be < Int16
	end

	class Int16le < Int16
		def initialize(v=nil, e=:little)
			super(v,e)
			@packstr = (self.e == :big) ? "n" : "v"
		end
	end

	class Int32 < Int
		def initialize(v=nil, e=:big)
			super(v,e,w=4)
			@packstr = (self.e == :big) ? "N" : "V"
		end

		def read(str)
			self.v = str.unpack(@packstr).first
			self
		end

		def to_s
			[(self.v || self.d)].pack(@packstr)
	 	end

	end

	class Int32be < Int32
	end

	class Int32le < Int32
		def initialize(v=nil, e=:little)
			super(v,e)
		end
	end

end	

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
