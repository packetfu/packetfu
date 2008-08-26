# Shell.rb is intended to be loaded or required within IRB, and provides
# a global variable ($packetfu_default) to hold network details.

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
|                            )( )( )( )( )(                            |
|                            )( )( )( )( )(                            |
(____________________________)            (____________________________)
            a mid-level packet manipulation library for ruby           

EOM
	end

require 'examples'
require 'packetfu'
include PacketFu

packetfu_ascii_art
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
