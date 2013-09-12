# -*- coding: binary -*-
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
# aliased to the PacketFu module proper. Sessions look something like
# this:
#
# == Example
#
#  irb(main):001:0> pkt = TCPPacket.new
#  => 00 1a c5 00 00 00 00 1a c5 00 00 00 08 00 45 00   ..............E.
#  00 28 62 9d 00 00 ff 06 59 33 00 00 00 00 00 00   .(b.....Y3......
#  00 00 d4 fb 00 00 18 c6 32 86 00 00 00 00 50 00   ........2.....P.
#  40 00 4f 9d 00 00                                 @.O...
#  irb(main):002:0> pkt.payload="I am totally up in your stack, twiddling your bits."
#  => "I am totally up in your stack, twiddling your bits."
#  irb(main):003:0> pkt.ip_saddr="1.2.3.4"
#  => "1.2.3.4"
#  irb(main):004:0> pkt.tcp_sport=13013
#  => 13013
#  irb(main):005:0> pkt.tcp_dport=808
#  => 808
#  irb(main):006:0> pkt.recalc
#  => {"eth_src"=>{"oui"=>{"local"=>0, "oui"=>6853, "b0"=>0, "b1"=>0, "b2"=>0, "multicast"=>0, "b3"=>0, "b4"=>0, "b5"=>0}, "nic"=>{"n1"=>0, "n2"=>0, "n3"=>0}}, "body"=>{"ip_tos"=>0, "ip_src"=>{"o1"=>1, "o2"=>2, "o3"=>3, "o4"=>4}, "body"=>{"tcp_ecn"=>{"c"=>0, "n"=>0, "e"=>0}, "tcp_dst"=>808, "tcp_win"=>16384, "body"=>"I am totally up in your stack, twiddling your bits.", "tcp_flags"=>{"fin"=>0, "psh"=>0, "syn"=>0, "rst"=>0, "ack"=>0, "urg"=>0}, "tcp_hlen"=>5, "tcp_ack"=>0, "tcp_urg"=>0, "tcp_seq"=>415642246, "tcp_sum"=>51184, "tcp_reserved"=>0, "tcp_opts"=>"", "tcp_src"=>13013}, "ip_dst"=>{"o1"=>0, "o2"=>0, "o3"=>0, "o4"=>0}, "ip_frag"=>0, "ip_proto"=>6, "ip_hl"=>5, "ip_len"=>91, "ip_sum"=>21754, "ip_id"=>25245, "ip_v"=>4, "ip_ttl"=>255}, "eth_proto"=>2048, "eth_dst"=>{"oui"=>{"local"=>0, "oui"=>6853, "b0"=>0, "b1"=>0, "b2"=>0, "multicast"=>0, "b3"=>0, "b4"=>0, "b5"=>0}, "nic"=>{"n1"=>0, "n2"=>0, "n3"=>0}}}
#  irb(main):007:0> pkt.to_f('/tmp/tcp-example.pcap')
#  => ["/tmp/tcp-example.pcap", 145, 1, 1220048597, 1]
#  irb(main):008:0> puts pkt.inspect_hex(2)
#  32 d5 03 28 7c 50 1f 01 00 00 00 00 50 00 40 00   2..(|P......P.@.
#  77 eb 00 00 49 20 61 6d 20 74 6f 74 61 6c 6c 79   w...I am totally
#  20 75 70 20 69 6e 20 79 6f 75 72 20 73 74 61 63    up in your stac
#  6b 2c 20 74 77 69 64 64 6c 69 6e 67 20 79 6f 75   k, twiddling you
#  72 20 62 69 74 73 2e                              r bits.
#  => nil

$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require './examples'
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

# Draws a picture. Includes a nunchuck, so you know that it's serious.
# I /think/ this is how you're supposed to spell it in a kana charset.
# http://jisho.org/words?jap=+%E3%83%91%E3%82%B1%E3%83%83%E3%83%88%E3%83%95&eng=&dict=edict
#
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
                               PacketFu
             a mid-level packet manipulation library for ruby

EOM
  end

@pcaprub_loaded = PacketFu.pcaprub_loaded?
# Displays a helpful banner.
def banner
  packetfu_ascii_art
  puts ">>> PacketFu Shell #{PacketFu.version}."
  if Process.euid.zero? && @pcaprub_loaded
    puts ">>> Use $packetfu_default.config for salient networking details."
    print "IP:  %-15s Mac: %s" % [$packetfu_default.ip_saddr, $packetfu_default.eth_saddr]
    puts "   Gateway: %s" % $packetfu_default.eth_daddr
    print "Net: %-15s" % [Pcap.lookupnet($packetfu_default.iface)][0]
    print "  " * 13 
    puts "Iface:   %s" % [($packetfu_default.iface)]
    puts ">>> Packet capturing/injecting enabled."
  else
    print ">>> Packet capturing/injecting disabled. "
    puts Process.euid.zero? ? "(no PcapRub)" : "(not root)"
  end
  puts "<>" * 36
end

# Silly wlan0 workaround
begin
  $packetfu_default = PacketFu::Config.new(Utils.whoami?) if(@pcaprub_loaded && Process.euid.zero?)
rescue RuntimeError
  $packetfu_default = PacketFu::Config.new(Utils.whoami?(:iface => 'wlan0')) if(@pcaprub_loaded && Process.euid.zero?)
end

banner
