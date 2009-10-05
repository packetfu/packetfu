module StructFu

	# Provides a primitive for creating strings, preceeded by
	# a type of length. By default, a string of length zero with
	# a one-byte length is presumed.  
	class IntString < Struct.new(:type, :string)

		def initialize(type=Int8,string='')
			unless type.ancestors.include? StructFu::Int
				raise StandardError, "Invalid length type (#{type.inspect}) associated with this String."
			else
				super(type.new,string)
				calc
			end
		end

		def calc
			type.v = string.to_s.size
			self.to_s
		end

		def to_s
			"#{type}#{string}"
		end

		# By redefining #string=, we can ensure the correct value
		# is calculated upon assignment. If you'd prefer to have
		# an incorrect value, use the syntax, obj[:string]="value"
		# instead. Note, by using the alternate form, you must
		# #calc before you can trust the type's value.
		def string=(s)
			self[:string] = s
			calc
		end

		# Read takes a string, assumes a type width as previously
		# defined upon initialization, but makes no guarantees
		# the type value isn't lying. You're on your own to test
		# for that. TODO: Think about implementing a more strict
		# version of this.
		def read(s)
			unless s[0,type.width].size == type.width
				raise StandardError, "String is too short for type #{type}"
			else
				type.read(s[0,type.width])
				self[:string] = s[type.width,s.size]
			end
			self.to_s
		end


	end

end

