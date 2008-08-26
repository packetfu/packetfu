# Shell.rb is intended to be loaded or required within IRB, and provides
# a global variable ($packetfu_default) to hold network details.

require 'examples'
require 'packetfu'
include PacketFu

puts ">>> PacketFu IRB Shell #{PacketFu.version}."

if Process.euid.zero?
	$packetfu_default = Config.new(Utils.whoami?)
	puts ">>> Running as root, packet capturing/injecting enabled."
	puts ">>> Type $packetfu_default.config for salient networking details."
else
	puts ">>> Running as non-root, packet capturing/injecting disabled."
end

puts ">>> For help, type packetfu_help"

def packetfu_help 
	puts <<-EOM
	"Some help text should really go here, as people might find it helpful."
	EOM
end
