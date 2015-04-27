require 'spec_helper'

include PacketFu

describe Utils do
  context "when using ifconfig" do
    it "should return a hash" do
      PacketFu::Utils.ifconfig().should be_a(::Hash)
    end

    it "should prevent non-interface values" do
      expect {
        PacketFu::Utils.ifconfig("not_an_interface")
      }.to raise_error(ArgumentError)
    end
  end
end