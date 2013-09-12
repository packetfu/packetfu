$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

PacketFu.packet_classes.each do |pclass|
  describe pclass, "peek format" do
    it "will display sensible peek information" do
      p = pclass.new
      p.respond_to?(:peek).should be_true
      p.peek.size.should be <= 80, p.peek.inspect
      p.peek.should match(/^[A-Z0-9?]../)
    end
  end
end
