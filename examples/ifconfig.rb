# -*- coding: binary -*-
$:.unshift(File.expand_path(File.dirname(__FILE__) + "/../lib/"))
require 'packetfu'

# ifconfig for Darwin
iface = ARGV[0] || 'en1'
config = PacketFu::Utils.ifconfig(iface)
print "#{RUBY_PLATFORM} => "
p config
