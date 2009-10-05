module StructFu

	# Provides a primitive for creating strings, preceeded by
	# an Int type of length. By default, a string of length zero with
	# a one-byte length is presumed.  
	class IntString < Struct.new(:int, :string, :mode)

		def initialize(int=Int8,string='')
			unless int.ancestors.include? StructFu::Int
				raise StandardError, "Invalid length int (#{int.inspect}) associated with this String."
			else
				super(int.new,string,nil)
				calc
			end
		end

		def calc
			int.v = string.to_s.size
			self.to_s
		end

		def to_s
			"#{int}#{string}"
		end

		# By redefining #string=, we can ensure the correct value
		# is calculated upon assignment. If you'd prefer to have
		# an incorrect value, use the syntax, obj[:string]="value"
		# instead. Note, by using the alternate form, you must
		# #calc before you can trust the int's value. Think of the
		# = assignment as "set to equal," while the []= assignment
		# as "boxing in" the value. Maybe.
		#
		# Example:
		#
		#  irb(main):001:0> o = StructFu::IntString.new
		#  => #<struct StructFu::IntString int=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, string="", strict=nil>
		#  irb(main):002:0> o.to_s
		#  => "\000"
		#  irb(main):003:0> o.string = "Hello!"
		#  => "Hello!"
		#  irb(main):004:0> o.to_s
		#  => "\006Hello!"
		#  irb(main):005:0> o[:string] = "Hi!"
		#  => "Hi!"
		#  irb(main):006:0> o.to_s
		#  => "\006Hi!"
		#  irb(main):007:0> o.calc
		#  => "\003Hi!"
		#  irb(main):008:0> o.to_s
		#  => "\003Hi!"
		#
		def string=(s)
			self[:string] = s
			calc
		end

		# Read takes a string, assumes an int width as previously
		# defined upon initialization, but makes no guarantees
		# the int value isn't lying. You're on your own to test
		# for that (or use parse() with a :mode set).
		def read(s)
			unless s[0,int.width].size == int.width
				raise StandardError, "String is too short for type #{int.class}"
			else
				int.read(s[0,int.width])
				self[:string] = s[int.width,s.size]
			end
			self.to_s
		end

		# parse() is like read(), except that it interprets the string, either
		# based on the declared length, or the actual length. Which strategy
		# is used is dependant on which :mode is set (with self.mode).
		#
		# :parse : Read the length, and then read in that many bytes of the string. The string may be truncated or padded out with nulls, as dictated by the value.
		# :fix   : Skip the length, read the rest of the string, then set the length to what it ought to be.
		# else   : If neither of these modes are set, just perfom a normal read(). This is the default.
		def parse(s)
			unless s[0,int.width].size == int.width
				raise StandardError, "String is too short for type #{int.class}"
			else
				case mode 
				when :parse
					int.read(s[0,int.width])
					self[:string] = s[int.width,int.value]
					if string.size < int.value
						self[:string] += ("\x00" * (int.value - self[:string].size))
					end
				when :fix
					self.string = s[int.width,s.size]
				else
					return read(s)
				end
			end
			self.to_s
		end


	end

end

