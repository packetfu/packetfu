#!/usr/bin/env ruby
require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu'

class OctetTest < Test::Unit::TestCase
	include PacketFu

	def setup
		@o = Octets.new
	end

	def test_create_octets
		assert_kind_of Octets, @o
	end

	def test_read
		s = "\x0a\x0a\x0a\x0b"
		@o.read s
		assert_equal(s, @o.to_s)
	end

	def test_dotted
		s = "\x0a\x0a\x0a\x01"
		@o.read s
		assert_equal("10.10.10.1", @o.to_x)
	end

	def test_numerical
		s = "\x00\x00\x00\x80"
		@o.read s
		assert_equal(128, @o.to_i)
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
