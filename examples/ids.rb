require 'packetfu' # Line 1, require PacketFu.
cap = PacketFu::Capture.new(:iface => ARGV[0], :start => true, :filter => "ip") # Line 2, set up the capture object.
loop {cap.stream.each {|pkt| packet = PacketFu::Packet.parse(pkt) # Line 3, loop the capture forever, parsing packets.
p "#{Time.now}: %s slammed %s" % [packet.ip_saddr, packet.ip_daddr] if packet.payload =~ /^\x04\x01{50}/ }} # Line 4, profit! I mean, alert!
