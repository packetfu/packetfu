#!/usr/bin/env ruby
$:.unshift File.expand_path(File.dirname(__FILE__) + "/../lib/")

require 'test/unit'

# Needed if you're using the gem version of pcaprub. Obviated in 1.9.
require 'packetfu'

class InjectTest < Test::Unit::TestCase

	def test_cap
		assert_nothing_raised { PacketFu::Capture }
	end

	def test_whoami
		assert_nothing_raised { PacketFu::Utils.whoami?(:iface => (ENV['IFACE'] || 'lo')) }
	end

	def test_to_w
		assert_equal(Process.euid, 0, "TEST FAIL: This test must be run as root")
		conf = PacketFu::Utils.whoami?(:iface => (ENV['IFACE'] || 'lo'))
		p = PacketFu::UDPPacket.new(:config => conf)
		p.udp_dport = 12345
		p.udp_sport = 12345
		p.payload = "PacketFu test packet"
		p.recalc
		assert p.to_w
	end

end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
