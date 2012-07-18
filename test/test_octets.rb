#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class OctetsTest < Test::Unit::TestCase
	include PacketFu

	def test_octets_read
		o = Octets.new
		o.read("\x04\x03\x02\x01")
		assert_equal("4.3.2.1", o.to_x)
	end

	def test_octets_read_quad
		o = Octets.new
		o.read_quad("1.2.3.4")
		assert_equal("1.2.3.4", o.to_x)
		assert_equal("\x01\x02\x03\x04", o.to_s)
		assert_equal(0x01020304, o.to_i)
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
