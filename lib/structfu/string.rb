module StructFu

	class String < ::String
		def read(str)
			self.replace str
			self
		end
	end

	# Provides a primitive for creating strings, preceeded by
	# an Int type of length. By default, a string of length zero with
	# a one-byte length is presumed.  
	class IntString < Struct.new(:int, :string, :mode)

		# TODO: Fix this so the string is first. Seems dumb now to have Int be first.
		def initialize(string='',int=Int8,mode=nil)
			unless int.respond_to?(:ancestors) && int.ancestors.include?(StructFu::Int)
				raise StandardError, "Invalid length (#{int.inspect}) associated with this String."
			else
				super(int.new,string,mode)
				calc
			end
		end

		def calc
			int.v = string.to_s.size
			self.to_s
		end

		def to_s
			if mode == :parse
				"#{int}" + [string].pack("a#{len}")
			elsif mode == :fix
				self.int.v = string.size
				"#{int}#{string}"
			else
				"#{int}#{string}"
			end
		end

		# By redefining #string=, we can ensure the correct value
		# is calculated upon assignment. If you'd prefer to have
		# an incorrect value, use the syntax, obj[:string]="value"
		# instead. Note, by using the alternate form, you must
		# #calc before you can trust the int's value. Think of the
		# = assignment as "set to equal," while the []= assignment
		# as "boxing in" the value. Maybe.
		def string=(s)
			self[:string] = s
			calc
		end

		# Shorthand for querying a length. Note that the usual "length"
		# and "size" refer to the number of elements of this struct.
		def len
			self[:int].value
		end

		# Override the size, if you must.
		def len=(i)
			self[:int].value=i
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
		# :parse : Read the length, and then read in that many bytes of the string. 
		#          The string may be truncated or padded out with nulls, as dictated by the value.
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

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
