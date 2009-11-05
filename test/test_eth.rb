#!/usr/bin/env ruby
require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'

class EthTest < Test::Unit::TestCase
	include PacketFu

	def setup
		@dst = "\x00\x03\x2f\x1a\x74\xde"
		@dstmac = "00:03:2f:1a:74:de"
		@src = "\x00\x1b\x11\x51\xb7\xce"
		@srcmac = "00-1b-11-51-b7-ce"
		@proto = "\x08\x00"
		@header = "00032f1a74de001b1151b7ce0800".scan(/../).map {
			|x| x.to_i(16)
		}.pack("C*")
		@ethmac = EthMac.new
		@eth = EthHeader.new
	end

	def test_ethmac
		@ethmac.read @dst
		assert_equal(@dst, @ethmac.to_s)
		assert_equal(0x32f, @ethmac.oui.oui)
		assert_equal("\x1a\x74\xde", @ethmac[:nic].to_s)
		assert_equal(222, @ethmac.nic.n2)
	end

	def test_ethmac_class
		@ethmac.read @dst
		e = EthMac.new.read @src
		assert_instance_of(PacketFu::EthMac, @ethmac)
		assert_instance_of(PacketFu::EthMac, e)
	end

	def test_eth
		@eth[:eth_dst] = @dst
		@eth[:eth_src] = @src
		@eth[:eth_proto] = @proto
		assert_equal(@header, @eth.to_s)
		assert_equal(@header, EthHeader.new.read(@header).to_s)
	end

	def test_macaddr
		assert_not_equal(@dst, @dstmac)
		assert_equal(@dstmac,EthHeader.str2mac(@dst))
		assert_equal(@dst, EthHeader.mac2str(@dstmac))
		e = EthHeader.new
		e.daddr=@dstmac
		e.saddr=@srcmac
		assert_equal(e.daddr, @dstmac)
		assert_equal(e.saddr, @srcmac.gsub(/-/,':'))
	end

end

class EthPacketTest < Test::Unit::TestCase
	include PacketFu

	def setup
		@pcaps = PcapFile.new.file_to_array(:f => 'sample.pcap')
		@header = @pcaps[0][0,14]
	end

	def test_create_packet
		p = EthPacket.new
		assert_kind_of EthPacket, p
		assert_kind_of EthHeader, p.headers[0]
		assert p.is_eth?
		assert_equal false, p.is_tcp?
		p.eth_dst = "\x00\x03\x2f\x1a\x74\xde"
		p.eth_src = "\x00\x1b\x11\x51\xb7\xce"
		p.eth_proto = 0x0800
		assert_equal @header, p.to_s[0,14]
	end

	def test_eth_new
		p = EthPacket.new(
		:eth_dst => "\x00\x03\x2f\x1a\x74\xde",
		:eth_src => "\x00\x1b\x11\x51\xb7\xce",
		:eth_proto => 0x0800)
		assert_equal @header, p.to_s[0,14]
	end


	def test_eth_packet_undecoded_body
		p = Packet.parse("A" * 100)
		assert p.is_eth?
		assert_equal(("A" * (100-14)), p.payload)
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
