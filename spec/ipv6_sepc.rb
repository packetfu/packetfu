require 'spec_helper'

include PacketFu


describe IPv6Packet do

  it 'sould set payload size on #recalc' do
    ipv6 = IPv6Packet.new
    ipv6.payload = "\0" * 14
    ipv6.recalc
    expect(ipv6.ipv6_len).to eq(14)
    ipv6.payload = "\0" * 255
    ipv6.recalc(:ipv6)
    expect(ipv6.ipv6_len).to eq(255)
  end

  it 'sould set payload size on #ipv6_recalc' do
    ipv6 = IPv6Packet.new
    ipv6.payload = "\0" * 3
    ipv6.ipv6_recalc
    expect(ipv6.ipv6_len).to eq(3)
    ipv6.payload = "\xff" * 12
    ipv6.ipv6_recalc(:ipv6_len)
    expect(ipv6.ipv6_len).to eq(12)
  end

end
