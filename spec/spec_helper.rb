
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

puts "rspec #{RSpec::Core::Version::STRING}"
if RSpec::Core::Version::STRING[0] == '3'
  require 'rspec/its'
  RSpec.configure do |config|
    #config.raise_errors_for_deprecations!
    config.expect_with :rspec do |c|
      c.syntax = [:expect, :should]
    end
  end
end


module FakePacket
  def layer
    7
  end
end

class PacketFu::FooPacket < PacketFu::Packet
  extend FakePacket
end

class PacketFu::BarPacket < PacketFu::Packet
  extend FakePacket
end

class PacketBaz
end

def add_fake_packets
  PacketFu.add_packet_class(PacketFu::FooPacket)
  PacketFu.add_packet_class(PacketFu::BarPacket)
end

def remove_fake_packets
  PacketFu.remove_packet_class(PacketFu::FooPacket)
  PacketFu.remove_packet_class(PacketFu::BarPacket)
end

remove_fake_packets
