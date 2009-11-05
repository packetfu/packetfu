# StructFu, a nifty way to leverage Ruby's built in Struct class
# to create meaningful binary data. 

module StructFu
	# Normally, self.size and self.length will refer to the Struct
	# size as an array. It's a hassle to redefine, so this introduces some
	# shorthand to get at the size of the resultant string.
	def sz
		self.to_s.size
	end

	alias len sz

	# A little metaprogramming. 
	def typecast(i)
		c = caller[0].match(/.*`([^']+)='/)[1]
		self[c.intern].read i
	end

end

require 'structfu/int.rb'
require 'structfu/string.rb'

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
