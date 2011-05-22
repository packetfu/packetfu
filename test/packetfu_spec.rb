require File.join("..","lib","packetfu")

describe PacketFu, "version information" do
	it "reports a version number" do
		PacketFu::VERSION.should == "1.0.2"
	end
	its(:version) {should eq PacketFu::VERSION} 

	it "can compare version strings" do
		PacketFu.binarize_version("1.2.3").should == 0x010203
		PacketFu.binarize_version("3.0").should == 0x030000
		PacketFu.at_least?("1.0").should be_true
		PacketFu.at_least?("4.0").should be_false
		PacketFu.older_than?("4.0").should be_true
		PacketFu.newer_than?("1.0").should be_true
	end
end

describe PacketFu, "instance variables" do
	it "should have a bunch of instance variables" do
		PacketFu.instance_variable_get(:@byte_order).should == :little
		PacketFu.instance_variable_get(:@pcaprub_loaded).should_not be_nil
	end
end

describe PacketFu, "pcaprub deps" do
	it "should check for pcaprub" do
		begin
			has_pcap = false
			require 'pcaprub'
			has_pcap = true
		rescue LoadError
		end
		if has_pcap
			PacketFu.instance_variable_get(:@pcaprub_loaded).should be_true
		else
			PacketFu.instance_variable_get(:@pcaprub_loaded).should be_false
		end
	end
end

describe PacketFu, "protocol requires" do
	it "should have some protocols defined" do
		PacketFu::EthPacket.should_not be_nil
		PacketFu::IPPacket.should_not be_nil
		PacketFu::TCPPacket.should_not be_nil
		expect { PacketFu::FakePacket }.to raise_error
	end
end

describe PacketFu, "packet class list management" do
	class FooPacket; end
	class BarPacket; end
	PacketFu.add_packet_class(FooPacket)
	PacketFu.add_packet_class(BarPacket)
	its(:packet_classes) {should include(FooPacket) and include(BarPacket)}
	it "should disallow non-classes as packet classes" do
		expect { PacketFu.add_packet_class("A String") }.to raise_error
	end
	its(:packet_prefixes) {should include("foo") and include("bar")}
	it "should disallow nonstandard packet class names" do
		class PacketBaz; end
		expect { PacketFu.add_packet_class(PacketBaz) }.to raise_error
	end
end
