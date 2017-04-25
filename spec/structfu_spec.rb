require 'spec_helper'

describe StructFu, "mixin methods" do
  before :each do
    class StructClass
      include StructFu
    end
    @sc = StructClass.new
  end

  it "should provide the basic StructFu methods" do
    expect(@sc).to respond_to(:sz)
    expect(@sc).to respond_to(:len)
    expect(@sc).to respond_to(:typecast)
    expect(@sc).to respond_to(:body=)
  end
end

describe StructFu::Int, "basic Int class" do
  before :each do
    @int = StructFu::Int.new(8)
  end

  it "should have an initial state" do
    new_int = StructFu::Int.new
    expect(new_int.value).to be_nil
    expect(new_int.endian).to be_nil
    expect(new_int.width).to be_nil
    expect(new_int.default).to eql(0)
  end

  it "should raise when to_s'ed directly" do
    expect{ @int.to_s}.to raise_error(StandardError, "StructFu::Int#to_s accessed, must be redefined.")
  end

  it "should have a value of 8" do
    expect(@int.value).to eql(8)
    expect(@int.to_i).to eql(8)
    expect(@int.to_f.to_s).to eql("8.0")
  end

  it "should read an integer" do
    @int.read(7)
    expect(@int.to_i).to eql(7)
  end
end

describe StructFu::Int8, "one byte value" do

  before :each do
    @int = StructFu::Int8.new(11)
  end

  it "should have an initial state" do
    new_int = StructFu::Int8.new
    expect(new_int.value).to be_nil
    expect(new_int.endian).to be_nil
    expect(new_int.width).to eql(1)
    expect(new_int.default).to eql(0)
  end

  it "should print a one character packed string" do
    expect(@int.to_s).to eql("\x0b")
  end

  it "should have a value of 11" do
    expect(@int.value).to eql(11)
    expect(@int.to_i).to eql(11)
    expect(@int.to_f.to_s).to eql("11.0")
  end

  it "should reset with a new integer" do
    @int.read(2)
    expect(@int.to_i).to eql(2)
    expect(@int.to_s).to eql("\x02")

    @int.read(254)
    expect(@int.to_i).to eql(254)
    expect(@int.to_s).to eql("\xfe".force_encoding("binary"))
  end

end

describe StructFu::Int16, "two byte value" do
  before :each do
    @int = StructFu::Int16.new(11)
  end

  it "should have an initial state" do
    new_int = StructFu::Int16.new
    expect(new_int.value).to be_nil
    expect(new_int.endian).to eql(:big)
    expect(new_int.width).to eql(2)
    expect(new_int.default).to eql(0)
  end

  it "should print a two character packed string" do
    expect(@int.to_s).to eql("\x00\x0b".force_encoding("binary"))
  end

  it "should have a value of 11" do
    expect(@int.value).to eql(11)
    expect(@int.to_i).to eql(11)
    expect(@int.to_f.to_s).to eql("11.0")
  end

  it "should reset with a new integer" do
    @int.read(2)
    expect(@int.to_i).to eql(2)
    expect(@int.to_s).to eql("\x00\x02")

    @int.read(254)
    expect(@int.to_i).to eql(254)
    expect(@int.to_s).to eql("\x00\xfe".force_encoding("binary"))
  end

  it "should be able to set endianness" do
    int_be = StructFu::Int16.new(11,:big)
    expect(int_be.to_s).to eql("\x00\x0b")

    int_le = StructFu::Int16.new(11,:little)
    expect(int_le.to_s).to eql("\x0b\x00")
  end

  it "should be able to switch endianness" do
    @int.endian.should == :big
    expect(@int.to_s).to eql("\x00\x0b")

    @int.endian = :little
    expect(@int.endian).to eql(:little)

    @int.read(11)
    expect(@int.to_s).to eql("\x0b\x00")
  end
end

describe StructFu::Int16le, "2 byte little-endian value" do

  before :each do
    @int = StructFu::Int16le.new(11)
  end

  it "should behave pretty much like any other 16 bit int" do
    expect(@int.to_s).to eql("\x0b\x00")
  end

  it "should raise when you try to change endianness" do
    expect { @int.endian = :big }.to raise_error(NoMethodError, /undefined method `endian='/)
    expect { @int.endian = :little }.to raise_error(NoMethodError, /undefined method `endian='/)
  end

end

describe StructFu::Int16be, "2 byte big-endian value" do

  before :each do
    @int = StructFu::Int16be.new(11)
  end

  it "should behave pretty much like any other 16 bit int" do
    expect(@int.to_s).to eql("\x00\x0b")
  end

  it "should raise when you try to change endianness" do
    expect { @int.endian = :big }.to raise_error(NoMethodError, /undefined method `endian='/)
    expect { @int.endian = :little }.to raise_error(NoMethodError, /undefined method `endian='/)
  end

end

describe StructFu::Int32, "four byte value" do

  before :each do
    @int = StructFu::Int32.new(11)
  end

  it "should have an initial state" do
    new_int = StructFu::Int32.new
    expect(new_int.value).to be_nil
    expect(new_int.endian).to eql(:big)
    expect(new_int.width).to eql(4)
    expect(new_int.default).to eql(0)
  end

  it "should print a four character packed string" do
    expect(@int.to_s).to eql("\x00\x00\x00\x0b")
  end

  it "should have a value of 11" do
    expect(@int.value).to eql(11)
    expect(@int.to_i).to eql(11)
    expect(@int.to_f.to_s).to eql("11.0")
  end

  it "should reset with a new integer" do
    @int.read(2)
    expect(@int.to_i).to eql(2)
    expect(@int.to_s).to eql("\x00\x00\x00\x02")

    @int.read(254)
    expect(@int.to_i).to eql(254)
    expect(@int.to_s).to eql("\x00\x00\x00\xfe".force_encoding("binary"))
  end

  it "should be able to set endianness" do
    int_be = StructFu::Int32.new(11,:big)
    expect(int_be.to_s).to eql("\x00\x00\x00\x0b")
    
    int_le = StructFu::Int32.new(11,:little)
    expect(int_le.to_s).to eql("\x0b\x00\x00\x00")
  end

  it "should be able to switch endianness" do
    @int.endian.should == :big
    expect(@int.to_s).to eql("\x00\x00\x00\x0b")

    @int.endian = :little
    expect(@int.endian).to eql(:little)
    
    @int.read(11)
    expect(@int.to_s).to eql("\x0b\x00\x00\x00")
  end

end

describe StructFu::Int32le, "4 byte little-endian value" do

  before :each do
    @int = StructFu::Int32le.new(11)
  end

  it "should behave pretty much like any other 32 bit int" do
    expect(@int.to_s).to eql("\x0b\x00\x00\x00")
  end

  it "should raise when you try to change endianness" do
    expect { @int.endian = :big }.to raise_error(NoMethodError, /undefined method `endian='/)
    expect { @int.endian = :little }.to raise_error(NoMethodError, /undefined method `endian='/)
  end

end

describe StructFu::Int32be, "4 byte big-endian value" do

  before :each do
    @int = StructFu::Int32be.new(11)
  end

  it "should behave pretty much like any other 32 bit int" do
    expect(@int.to_s).to eql("\x00\x00\x00\x0b")
  end

  it "should raise when you try to change endianness" do
    expect { @int.endian = :big }.to raise_error(NoMethodError, /undefined method `endian='/)
    expect { @int.endian = :little }.to raise_error(NoMethodError, /undefined method `endian='/)
  end

end

describe StructFu::String, "a sligtly more special String" do

  before :each do
    @str = StructFu::String.new("Oi, a string")
  end

  it "should behave pretty much like a string" do
    expect(@str).to be_kind_of(String)
  end

  it "should have a read method" do
    expect(@str).to respond_to(:read)
  end

  it "should read data like other StructFu things" do
    @str.read("hello")
    expect(@str).to eql("hello")
  end

end

describe StructFu::IntString do

  it "should be" do
    StructFu::IntString.should be
  end

  it "should have a length and value" do
    istr = StructFu::IntString.new("Avast!")
    expect(istr.to_s).to eql("\x06Avast!")
  end

  it "should have a 16-bit length and a value" do
    istr = StructFu::IntString.new("Avast!",StructFu::Int16)
    expect(istr.to_s).to eql("\x00\x06Avast!")
  end

  it "should have a 32-bit length and a value" do
    istr = StructFu::IntString.new("Avast!",StructFu::Int32)
    expect(istr.to_s).to eql("\x00\x00\x00\x06Avast!")
  end

  before :each do
    @istr = StructFu::IntString.new("Avast!",StructFu::Int32)
  end

  it "should report the correct length with a new string" do
    expect(@istr.to_s).to eql("\x00\x00\x00\x06Avast!")

    @istr.string = "Ahoy!"
    expect(@istr.to_s).to eql("\x00\x00\x00\x05Ahoy!")
  end

  it "should report the correct length with a new string" do
    @istr.string = "Ahoy!"
    expect(@istr.to_s).to eql("\x00\x00\x00\x05Ahoy!")
  end

  it "should keep the old length with a new string" do
    @istr[:string] = "Ahoy!"
    expect(@istr.to_s).to eql("\x00\x00\x00\x06Ahoy!")
  end

  it "should allow for adjusting the length manually" do
    @istr.len = 16
    expect(@istr.to_s).to eql("\x00\x00\x00\x10Avast!")
  end

  it "should read in an expected string" do
    data = "\x00\x00\x00\x09Yo ho ho!"
    @istr.read(data)
    expect(@istr.to_s).to eql(data)
  end

  it "should raise when a string is too short" do
    data = "\x01A"
    expect{ @istr.read(data) }.to raise_error(StandardError, "String is too short for type StructFu::Int32")
  end
end
