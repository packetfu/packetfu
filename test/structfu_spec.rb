require File.join("..","lib","packetfu")

describe StructFu, "mixin methods" do
	class StructClass
		include StructFu
	end
	sc = StructClass.new
	it "should provide the basic StructFu methods" do
		sc.respond_to?(:sz).should be_true
		sc.respond_to?(:len).should be_true
		sc.respond_to?(:typecast).should be_true
		sc.respond_to?(:body=).should be_true
	end
end	

describe StructFu::Int, "basic Int class" do

	before :each do
		@int = StructFu::Int.new(8)
	end

	it "should have an initial state" do
		new_int = StructFu::Int.new
		new_int.value.should be_nil
		new_int.endian.should be_nil
		new_int.width.should be_nil
		new_int.default.should == 0
	end

	it "should raise when to_s'ed directly" do
		expect { @int.to_s}.to raise_error
	end

	it "should have a value of 8" do
		@int.value.should == 8
		@int.to_i.should == 8
		@int.to_f.to_s.should == "8.0"
	end

	it "should read an integer" do
		@int.read(7)
		@int.to_i.should == 7
	end

end

describe StructFu::Int8, "one byte value" do

	before :each do
		@int = StructFu::Int8.new(11)
	end

	it "should have an initial state" do
		new_int = StructFu::Int8.new
		new_int.value.should be_nil
		new_int.endian.should be_nil
		new_int.width.should == 1
		new_int.default.should == 0
	end

	it "should print a one character packed string" do
		@int.to_s.should == "\x0b"
	end

	it "should have a value of 11" do
		@int.value.should == 11
		@int.to_i.should == 11
		@int.to_f.to_s.should == "11.0"
	end

	it "should reset with a new integer" do
		@int.read(2)
		@int.to_i.should == 2
		@int.to_s.should == "\x02"
		@int.read(254)
		@int.to_i.should == 254
		@int.to_s.should == "\xfe"
	end

end

describe StructFu::Int16, "two byte value" do

	before :each do
		@int = StructFu::Int16.new(11)
	end

	it "should have an initial state" do
		new_int = StructFu::Int16.new
		new_int.value.should be_nil
		new_int.endian.should == :big
		new_int.width.should == 2
		new_int.default.should == 0
	end

	it "should print a two character packed string" do
		@int.to_s.should == "\x00\x0b"
	end

	it "should have a value of 11" do
		@int.value.should == 11
		@int.to_i.should == 11
		@int.to_f.to_s.should == "11.0"
	end

	it "should reset with a new integer" do
		@int.read(2)
		@int.to_i.should == 2
		@int.to_s.should == "\x00\x02"
		@int.read(254)
		@int.to_i.should == 254
		@int.to_s.should == "\x00\xfe"
	end

	it "should be able to set endianness" do
		int_be = StructFu::Int16.new(11,:big)
		int_be.to_s.should == "\x00\x0b"
		int_le = StructFu::Int16.new(11,:little)
		int_le.to_s.should == "\x0b\x00"
	end

	it "should be able to switch endianness" do
		@int.endian.should == :big
		@int.to_s.should == "\x00\x0b"
		@int.endian = :little
		@int.endian.should == :little
		@int.read(11)
		@int.to_s.should == "\x0b\x00"
	end

end

describe StructFu::Int16le, "2 byte little-endian value" do

	before :each do
		@int = StructFu::Int16le.new(11)
	end

	it "should behave pretty much like any other 16 bit int" do
		@int.to_s.should == "\x0b\x00"
	end

	it "should raise when you try to change endianness" do
		expect { @int.endian = :big }.to raise_error
		expect { @int.endian = :little }.to raise_error
	end

end

describe StructFu::Int16be, "2 byte big-endian value" do

	before :each do
		@int = StructFu::Int16be.new(11)
	end

	it "should behave pretty much like any other 16 bit int" do
		@int.to_s.should == "\x00\x0b"
	end

	it "should raise when you try to change endianness" do
		expect { @int.endian = :big }.to raise_error
		expect { @int.endian = :little }.to raise_error
	end

end

describe StructFu::Int32, "four byte value" do

	before :each do
		@int = StructFu::Int32.new(11)
	end

	it "should have an initial state" do
		new_int = StructFu::Int32.new
		new_int.value.should be_nil
		new_int.endian.should == :big
		new_int.width.should == 4
		new_int.default.should == 0
	end

	it "should print a four character packed string" do
		@int.to_s.should == "\x00\x00\x00\x0b"
	end

	it "should have a value of 11" do
		@int.value.should == 11
		@int.to_i.should == 11
		@int.to_f.to_s.should == "11.0"
	end

	it "should reset with a new integer" do
		@int.read(2)
		@int.to_i.should == 2
		@int.to_s.should == "\x00\x00\x00\x02"
		@int.read(254)
		@int.to_i.should == 254
		@int.to_s.should == "\x00\x00\x00\xfe"
	end

	it "should be able to set endianness" do
		int_be = StructFu::Int32.new(11,:big)
		int_be.to_s.should == "\x00\x00\x00\x0b"
		int_le = StructFu::Int32.new(11,:little)
		int_le.to_s.should == "\x0b\x00\x00\x00"
	end

	it "should be able to switch endianness" do
		@int.endian.should == :big
		@int.to_s.should == "\x00\x00\x00\x0b"
		@int.endian = :little
		@int.endian.should == :little
		@int.read(11)
		@int.to_s.should == "\x0b\x00\x00\x00"
	end

end

describe StructFu::Int32le, "4 byte little-endian value" do

	before :each do
		@int = StructFu::Int32le.new(11)
	end

	it "should behave pretty much like any other 32 bit int" do
		@int.to_s.should == "\x0b\x00\x00\x00"
	end

	it "should raise when you try to change endianness" do
		expect { @int.endian = :big }.to raise_error
		expect { @int.endian = :little }.to raise_error
	end

end

describe StructFu::Int32be, "4 byte big-endian value" do

	before :each do
		@int = StructFu::Int32be.new(11)
	end

	it "should behave pretty much like any other 32 bit int" do
		@int.to_s.should == "\x00\x00\x00\x0b"
	end

	it "should raise when you try to change endianness" do
		expect { @int.endian = :big }.to raise_error
		expect { @int.endian = :little }.to raise_error
	end

end
