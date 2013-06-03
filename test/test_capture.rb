#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'


class CaptureTest < Test::Unit::TestCase

	def test_cap
		assert_nothing_raised { PacketFu::Capture }
	end

	def test_whoami
		assert_nothing_raised { PacketFu::Utils.whoami?(:iface => (ENV['IFACE'] || 'lo')) }
	end
	
	def test_new
		cap = PacketFu::Capture.new
		assert_kind_of PacketFu::Capture, cap
		cap = PacketFu::Capture.new(
			:filter => 'tcp and dst host 1.2.3.4'
		)
	end
	
	def test_filter
		daddr = PacketFu::Utils.rand_routable_daddr.to_s
		cap = PacketFu::Capture.new(
			:filter => "icmp and dst host #{daddr}"
		)
		cap.start
		%x{ping -c 1 #{daddr}}
		sleep 3
		cap.save
		cap.array.each {|p| puts PacketFu::Packet.parse(p).inspect}
		assert cap.array.size == 1
	end

end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
