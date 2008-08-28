# == Synopsis
#
# packetfu-shell.rb is intended for IRB consumption, and providing an
# interactive interface for PacketFu experimentation.
#
# == Usage
#
#   irb -r packetfu-shell.rb
# or
#   sudo irb -r packetfu-shell.rb
#
# If run as root, packet capturing/injecting is available, which includes
# access to Utils.whoami?
#
# Once loaded, the PacketFu module is mixed in, and Utils commands are
# aliased to the PacketFu module proper. Thus, commands will look like:
#
#   irb(main):001:0> pkt = TCPPacket.new(:config => whoami?)
#   irb(main):002:0> pkt.to_f
#   irb(main):003:0> arp "192.168.1.1"

def packetfu_ascii_art
	puts <<EOM
 _______  _______  _______  _        _______ _________ _______          
(  ____ )(  ___  )(  ____ \\| \\    /\\(  ____ \\\\__   __/(  ____ \\|\\     /|
| (    )|| (   ) || (    \\/|  \\  / /| (    \\/   ) (   | (    \\/| )   ( |
| (____)|| (___) || |      |  (_/ / | (__       | |   | (__    | |   | |
|  _____)|  ___  || |      |   _ (  |  __)      | |   |  __)   | |   | |
| (      | (   ) || |      |  ( \\ \\ | (         | |   | (      | |   | |
| )      | )   ( || (____/\\|  /  \\ \\| (____/\\   | |   | )      | (___) |
|/       |/     \\|(_______/|_/    \\/(_______/   )_(   |/       (_______)
 ____________________________              ____________________________
(                            )            (                            )
| 01000001 00101101 01001000 )( )( )( )( )( 00101101 01000001 00100001 |
|                            )( )( )( )( )(                            |
(____________________________)            (____________________________)
            a mid-level packet manipulation library for ruby           

EOM
	end

require 'examples'
require 'packetfu'

module PacketFu
	def whoami?(args={})
		Utils.whoami?(args)
	end
	def arp(arg)
		Utils.arp(arg)
	end
end

include PacketFu

def banner
	packetfu_ascii_art
	puts ">>> PacketFu Shell #{PacketFu.version}."
	if Process.euid.zero?
		puts ">>> Use $packetfu_default.config for salient networking details."
		print "IP:  %-15s Mac: %s" % [$packetfu_default.ip_saddr, $packetfu_default.eth_saddr]
		puts "   Gateway: %s" % $packetfu_default.eth_daddr
		print "Net: %-15s" % [Pcap.lookupnet(Pcap.lookupdev)][0]
		print "  " * 13 
		puts "Iface:   %s" % [Pcap.lookupdev]
		puts ">>> Running as root, packet capturing/injecting enabled."
	else
		puts ">>> Running as non-root, packet capturing/injecting disabled."
	end
	puts "<>" * 36
end

$packetfu_default = Config.new(Utils.whoami?) if Process.euid.zero?
banner
