#!/usr/bin/env ruby
require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'

class TcpEcnTest < Test::Unit::TestCase
	include PacketFu

	def test_tcp_ecn_set
		t = TcpEcn.new
		assert_kind_of TcpEcn, t
		assert_equal(0, t.to_i)
		t.n = 1
		assert_equal(4, t.to_i)
		t.c = 1
		assert_equal(6, t.to_i)
		t.e = 1
		assert_equal(7, t.to_i)
	end

	def test_tcp_ecn_read
		t = TcpEcn.new
		assert_kind_of TcpEcn, t
		t.read("\x30\xc0")
		assert_equal(0, t.n)
		assert_equal(1, t.c)
		assert_equal(1, t.e)
		t.read("\xa3\x38")
		assert_equal(1, t.n)
		assert_equal(0, t.c)
		assert_equal(0, t.e)
	end


end

class TcpFlagsTest < Test::Unit::TestCase
	include PacketFu

	def test_tcp_flags_set
		t = TcpFlags.new
		assert_kind_of TcpFlags, t
		t.fin = 1
		t.ack = 1
		assert_equal(0x11, t.to_i)
		t.fin = 0
		t.syn = 1
		assert_equal(0x12, t.to_i)
	end

	def test_tcp_flags_read
		t = TcpFlags.new
		t.read("\x11")
		assert_equal(1, t.fin)
		assert_equal(1, t.ack)
		t.read("\xa6")
		assert_equal(1, t.urg)
		assert_equal(1, t.rst)
		assert_equal(1, t.syn)
		assert_equal(0, t.psh)
		assert_equal(0, t.ack)
		assert_equal(0, t.fin)
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
