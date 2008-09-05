require 'packetfu' # Line 0, require PacketFu for an IDS in 6 lines or less!
cap = PacketFu::Capture.new(:iface => ARGV[0], :start => true, :filter => "ip") # Line 1, set up the capture object.
attack_patterns = ["^gotcha", "owned!*$", "^\x04[^\x00]{50}"] # Line 2, define your attack patterns.
loop {cap.stream.each {|pkt| packet = PacketFu::Packet.parse(pkt) # Line 3, loop the capture forever, parsing packets.
 attack_patterns.each {|sig| hit = packet.payload.scan(/#{sig}/i) || nil # Line 4, test the packet for a match against one of the attacks.
 puts "#{Time.now}: %s attacked %s [%s]" % [packet.ip_saddr, packet.ip_daddr, sig.inspect] unless hit.size.zero? }}} # Line 5, profit! I mean, alert!
