require 'singleton'
module PacketFu

	# Utils is a collection of various and sundry network utilities that are useful for packet
	# manipulation.
	class Utils
		include Singleton

		# Returns the MAC address of an IP address, or nil if it's not responsive to arp. Takes
		# a dotted-octect notation of the target IP address, as well as a number of parameters:
		#
		# === Parameters
		#   :eth_saddr
		#    Source MAC address. Defaults to $packetfu_iam[:eth_saddr]
		#   :ip_saddr
		#    Source IP address. Defaults to $packetfu_iam[:ip_saddr]
		#   :flavor
		#    The flavor of the ARP request.
		#   :timeout
		#    Timeout in seconds. Default is 3.
		#
		#  === Example
		#    PacketFu::Utils::arp("192.168.1.1") #=> "00:18:39:01:33:70"
		#    PacketFu::Utils::arp("192.168.1.1", :timeout => 5, :flavor => :hp_deskjet)
		#  
		#  === Warning
		#  
		#  It goes without saying, spewing forged ARP packets on your network is a great way to really
		#  irritate your co-workers.
		def self.arp(target_ip,args={})
			arp_pkt = PacketFu::ARPPacket.new(:flavor => (args[:flavor] || :none))
			arp_pkt.eth_saddr = arp_pkt.arp_saddr_mac = (args[:eth_saddr] || $packetfu_iam[:eth_saddr])
			arp_pkt.eth_daddr = "ff:ff:ff:ff:ff:ff"
			arp_pkt.arp_daddr_mac = "00:00:00:00:00:00"
			arp_pkt.arp_saddr_ip = (args[:ip_saddr] || $packetfu_iam[:ip_saddr])
			arp_pkt.arp_daddr_ip = target_ip 
			# Stick the Capture object in its own thread.
			cap_thread = Thread.new do
				target_mac = nil
				cap = PacketFu::Capture.new(:start => true, 
				:filter => "arp src #{target_ip} and ether dst #{arp_pkt.eth_saddr}")
				arp_pkt.to_w # Shorthand for sending single packets to the default interface.
				timeout = 0
				while target_mac.nil? && timeout <= (args[:timeout] || 3)
					if cap.save > 0
						arp_response = PacketFu::Packet.parse(cap.array[0])
						target_mac = arp_response.arp_saddr_mac if arp_response.arp_saddr_ip = target_ip
					end
					timeout += 0.1
					sleep 0.1 # Check for a response ten times per second.
				end
				target_mac
			end # cap_thread
			cap_thread.value
		end
	end
end
