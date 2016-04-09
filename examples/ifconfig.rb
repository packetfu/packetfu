# -*- coding: binary -*-
require 'packetfu'

# ifconfig for Darwin
iface = ARGV[0] || 'en1'
config = PacketFu::Utils.ifconfig(iface)
print "#{RUBY_PLATFORM} => "
p config
