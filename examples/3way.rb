#!/usr/bin/env ruby

# 3way.rb demonstrates how to set up a simple ESTABLISHED state between
# a remote client and a fake PacketFU-driven server.
#
# Usage: 3way.rb iface port
#
# Note, you will need to suppress the server's normal response (RSTs) to
# the given port for this to work. This is easily done with iptables and
# friends (personally, I use ufw).

$iface = ARGV[0] || "eth0"
$port = (ARGV[1] || "13013").to_i

require 'packetfu'
cap = PacketFu::Capture.new(:iface => $iface, :start => true, :filter => "tcp and port #{$port}")
caught = false
while caught == false do
	cap.stream.each do |pkt|
		packet = PacketFu::Packet.parse pkt
		if packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 0
			puts "Got a SYN: with seq = #{seq = packet.tcp_seq} from #{packet.ip_saddr}"
			ack_packet = PacketFu::TCPPacket.new(:config => PacketFu::Utils.whoami?)
			ack_packet.ip_daddr= packet.ip_saddr
			ack_packet.tcp_src = $port
			ack_packet.tcp_dst = packet.tcp_src
			ack_packet.tcp_ack = seq + 1
			ack_packet.tcp_flags.syn = 1
			ack_packet.tcp_flags.ack = 1
			ack_packet.recalc
			puts "Sending SYN ACK..."
			ack_packet.to_w("#{$iface}")
		end
		if packet.tcp_flags.syn == 0 && packet.tcp_flags.ack == 1 && packet.tcp_flags.fin == 0
			puts "Got 'im! Check your netstat state on the remote machine!"
			caught = true
		end
	end
end
