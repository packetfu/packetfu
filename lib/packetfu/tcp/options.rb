module PacketFu

	# TcpOption is the base class for all TCP options. Note that TcpOption#len 
	# returns the size of the entire option, while TcpOption#optlen is the struct 
	# for the TCP Option Length field.
	#
	# Subclassed options should set the correct TcpOption#kind by redefining 
	# initialize. They should also deal with various value types there by setting
	# them explicitly with an accompanying StructFu#typecast for the setter. 
	#
	# By default, values are presumed to be strings, unless they are Numeric, in
	# which case a guess is made to the width of the Numeric based on the given
	# optlen. 
	#
	# Note that normally, optlen is /not/ enforced for directly setting values,
	# so the user is perfectly capable of setting incorrect lengths.
	class TcpOption < Struct.new(:kind, :optlen, :value)

		include StructFu

		def initialize(args={})
			super(
				Int8.new(args[:kind]),
				Int8.new(args[:optlen])
			)
			if args[:value].kind_of? Numeric
				self[:value] = case args[:optlen]
											 when 3; Int8.new(args[:value])
											 when 4; Int16.new(args[:value])
											 when 6; Int32.new(args[:value])
											 else; StructFu::String.new.read(args[:value])
											 end
			else
				self[:value] = StructFu::String.new.read(args[:value])
			end
		end

		def to_s
			self[:kind].to_s + 
			(self[:optlen].value.nil? ? nil : self[:optlen]).to_s +
			(self[:value].nil? ? nil : self[:value]).to_s
		end

		def read(str)
			return self if str.nil?
			self[:kind].read(str[0,1])
			if str[1,1]
				self[:optlen].read(str[1,1])
				if str[2,1] && optlen.value > 2
					self[:value].read(str[2,optlen.value-2])
				end
			end
			self
		end

		def decode
			unk = "unk-#{self.kind.to_i}"
			(self[:optlen].to_i > 2 && self[:value].to_s.size > 1) ? [unk,self[:value]].join(":") : unk
		end

		def kind=(i); typecast i; end
		def optlen=(i); typecast i; end

		def value=(i)
			if i.kind_of? Numeric
				typecast i
			elsif i.respond_to? :to_s
				self[:value] = i
			else
				self[:value] = ''
			end
		end

		# Generally, encoding a value is going to be just a read. Some
		# options will treat things a little differently; TS for example,
		# takes two values and concatenates them.
		def encode(str)
			self[:value] = self.class.new(:value => str).value
		end

		def has_optlen?
			(kind.value && kind.value < 2) ? false : true
		end
		
		def has_value?
			(value.respond_to? :to_s && value.to_s.size > 0) ? false : true
		end

		# http://www.networksorcery.com/enp/protocol/tcp/option000.htm
		class EOL < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 0)
				)
			end

			def decode
				"EOL"
			end

		end

		# http://www.networksorcery.com/enp/protocol/tcp/option001.htm
		class NOP < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 1)
				)
			end

			def decode
				"NOP"
			end

		end

		# http://www.networksorcery.com/enp/protocol/tcp/option002.htm
		class MSS < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 2,
										 :optlen => 4
										)
				)
				self[:value] = Int16.new(args[:value])
			end

			def value=(i); typecast i; end

			def decode
				if self[:optlen].to_i == 4
					"MSS:#{self[:value].to_i}"
				else
					"MSS-bad:#{self[:value]}"
				end
			end

		end

		# http://www.networksorcery.com/enp/protocol/tcp/option003.htm
		class WS < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 3,
										 :optlen => 3
										)
				)
				self[:value] = Int8.new(args[:value])
			end

			def value=(i); typecast i; end

			def decode
				if self[:optlen].to_i == 3
					"WS:#{self[:value].to_i}"
				else
					"WS-bad:#{self[:value]}"
				end
			end

		end

		# http://www.networksorcery.com/enp/protocol/tcp/option004.htm
		class SACKOK < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 4,
										 :optlen => 2)
				)
			end

			def decode
				if self[:optlen].to_i == 2
					"SACKOK"
				else
					"SACKOK-bad:#{self[:value]}"
				end
			end

		end

		# http://www.networksorcery.com/enp/protocol/tcp/option004.htm
		# Note that SACK always takes its optlen from the size of the string.
		class SACK < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 5,
										 :optlen => ((args[:value] || "").size + 2)
										)
				)
			end

			def optlen=(i); typecast i; end

			def value=(i)
				self[:optlen] = Int8.new(i.to_s.size + 2)
				self[:value] = StructFu::String.new(i)
			end

			def decode
					"SACK:#{self[:value]}"
			end

			def encode(str)
				temp_obj = self.class.new(:value => str)
				self[:value] = temp_obj.value
				self[:optlen] = temp_obj.optlen.value
				self
			end

		end

		# http://www.networksorcery.com/enp/protocol/tcp/option006.htm
		class ECHO < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 6,
										 :optlen => 6
										)
				)
			end

			def decode
				if self[:optlen].to_i == 6
					"ECHO:#{self[:value]}"
				else
					"ECHO-bad:#{self[:value]}"
				end
			end

		end

		# http://www.networksorcery.com/enp/protocol/tcp/option007.htm
		class ECHOREPLY < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 7,
										 :optlen => 6
										)
				)
			end

			def decode
				if self[:optlen].to_i == 6
					"ECHOREPLY:#{self[:value]}"
				else
					"ECHOREPLY-bad:#{self[:value]}"
				end
			end

		end

		# http://www.networksorcery.com/enp/protocol/tcp/option008.htm
		class TS < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 8,
										 :optlen => 10
										)
				)
				self[:value] = StructFu::String.new.read(args[:value] || "\x00" * 8) 
			end

			def decode
				if self[:optlen].to_i == 10
					val1,val2 = self[:value].unpack("NN")
					"TS:#{val1};#{val2}"
				else
					"TS-bad:#{self[:value]}"
				end
			end

			def encode(str)
				if str =~ /^([0-9]+);([0-9]+)$/
					tsval,tsecr = str.split(";").map {|x| x.to_i}
					if tsval <= 0xffffffff && tsecr <= 0xffffffff
						self[:value] = StructFu::String.new([tsval,tsecr].pack("NN"))
					else
						self[:value] = StructFu::String.new(str)
					end
				else
					self[:value] = StructFu::String.new(str)
				end
			end

		end

	end

	class TcpOptions < Array

		include StructFu

		# If args[:pad] is set, the options line is automatically padded out
		# with NOPs. 
		def to_s(args={})
			opts = self.map {|x| x.to_s}.join
			if args[:pad]
				unless (opts.size % 4).zero?
					(4 - (opts.size % 4)).times { opts << "\x01" }
				end
			end
			opts
		end

		def read(str)
			self.clear if self.size > 0
			return self if(!str.respond_to? :to_s || str.nil?)
			i = 0
			while i < str.to_s.size
				this_opt = case str[i,1].unpack("C").first
									 when 0; TcpOption::EOL.new
									 when 1; TcpOption::NOP.new
									 when 2; TcpOption::MSS.new
									 when 3; TcpOption::WS.new
									 when 4; TcpOption::SACKOK.new
									 when 5; TcpOption::SACK.new
									 when 6; TcpOption::ECHO.new
									 when 7; TcpOption::ECHOREPLY.new
									 when 8; TcpOption::TS.new
									 else; TcpOption.new
									 end
				this_opt.read str[i,str.size]
				unless this_opt.has_optlen?
					this_opt.value = nil
					this_opt.optlen = nil
				end
				self << this_opt
				i += this_opt.sz
			end
			self
		end

		# Decode parses the TcpOptions object's member options, and produces a
		# human-readable string by iterating over each element's decode() function.
		# If TcpOptions elements were not initially created as TcpOptions, an
		# attempt will be made to convert them. 
		#
		# The output of decode is suitable as input for TcpOptions#encode.
		def decode
			decoded = self.map do |x| 
				if x.kind_of? TcpOption
					x.decode
				else
					x = TcpOptions.new.read(x).decode
				end
			end
			decoded.join(",")
		end

		# Encode takes a human-readable string and appends the corresponding
		# binary options to the TcpOptions object. To completely replace the contents
		# of the object, use TcpOptions#encode! instead.
		# 
		# Options are comma-delimited, and are identical to the output of the
		# TcpOptions#decode function. Note that the syntax can be unforgiving, so
		# it may be easier to create the subclassed TcpOptions themselves directly,
		# but this method can be less typing if you know what you're doing.
		# 
		# Note that by using TcpOptions#encode, strings supplied as values which
		# can be converted to numbers will be converted first.
		#
		# == Example
		#
		#   t = TcpOptions.new
		#   t.encode("MS:1460,WS:6")
		#		t.to_s # => "\002\004\005\264\002\003\006"
		#		t.encode("NOP")
		#		t.to_s # => "\002\004\005\264\002\003\006\001"
		def encode(str)
			opts = str.split(/[\s]*,[\s]*/)
			opts.each do |o|
				kind,value = o.split(/[\s]*:[\s]*/)
				klass = TcpOption.const_get(kind.upcase)
				value = value.to_i if value =~ /^[0-9]+$/
				this_opt = klass.new
				this_opt.encode(value)
				self << this_opt
			end
			self
		end

		# Like TcpOption#encode, except the entire contents are replaced.
		def encode!(str)
			self.clear if self.size > 0
			encode(str)
		end

	end

end
