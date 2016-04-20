# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu'

module PacketFu

  describe PcapNG do
  end

  module PcapNG

    describe UnknownBlock do

      before(:each) { @ub = UnknownBlock.new }

      it 'should have correct initialization values' do
        expect(@ub).to be_a(UnknownBlock)
        expect(@ub.endian).to eq(:little)
        expect(@ub.type.to_i).to eq(0)
        expect(@ub.block_len.to_i).to eq(UnknownBlock::MIN_SIZE)
        expect(@ub.block_len2).to eq(@ub.block_len)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = "\xff\xff\xff\xff\x0c\x00\x00\x00\x0c\x00\x00\x00"
          expect { @ub.read(str) }.to_not raise_error
          expect(@ub.type.to_i).to eq(0xffffffff)
          expect(@ub.block_len.to_i).to eq(12)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '..', 'test', 'sample.pcapng')) do |f|
            @ub.read(f)
          end
          expect(@ub.type.to_i).to eq(0x0a0d0d0a)
          expect(@ub.block_len.to_i).to eq(52)
        end
      end
    end

    describe SHB do

      before(:each) { @shb = SHB.new }

      it 'should have correct initialization values' do
        expect(@shb).to be_a(SHB)
        expect(@shb.endian).to eq(:little)
        expect(@shb.type).to eq(PcapNG::SHB_TYPE)
        expect(@shb.block_len.to_i).to eq(SHB::MIN_SIZE)
        expect(@shb.magic.to_s).to eq(SHB::MAGIC_LITTLE)
        expect(@shb.ver_major.to_i).to eq(1)
        expect(@shb.ver_minor.to_i).to eq(0)
        expect(@shb.section_len.to_i).to eq(0)
        expect(@shb.block_len2).to eq(@shb.block_len)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = ::File.read(::File.join(__dir__, '..', 'test', 'sample.pcapng'), 52)
          expect { @shb.read(str) }.to_not raise_error
          expect(@shb.block_len.to_i).to eq(52)
          expect(@shb.has_options?).to be(true)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '..', 'test', 'sample.pcapng')) do |f|
            @shb.read(f)
          end
          expect(@shb.block_len.to_i).to eq(52)
          expect(@shb.has_options?).to be(true)
        end
      end
    end

    describe IDB do

      before(:each) { @idb = IDB.new }

      it 'should have correct initialization values' do
        expect(@idb).to be_a(IDB)
        expect(@idb.endian).to eq(:little)
        expect(@idb.type.to_i).to eq(PcapNG::IDB_TYPE.to_i)
        expect(@idb.link_type.to_i).to eq(PcapNG::LINKTYPE_ETHERNET)
        expect(@idb.snaplen.to_i).to eq(0)
        expect(@idb.block_len.to_i).to eq(IDB::MIN_SIZE)
        expect(@idb.block_len2).to eq(@idb.block_len)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = ::File.read(::File.join(__dir__, '..', 'test', 'sample.pcapng'))[52, 32]
          expect { @idb.read(str) }.to_not raise_error
          expect(@idb.type.to_i).to eq(PcapNG::IDB_TYPE.to_i)
          expect(@idb.block_len.to_i).to eq(32)
          expect(@idb.link_type.to_i).to eq(PcapNG::LINKTYPE_ETHERNET)
          expect(@idb.snaplen.to_i).to eq(0xffff)
          expect(@idb.has_options?).to be(true)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '..', 'test', 'sample.pcapng')) do |f|
            f.seek(52, :CUR)
            @idb.read f
          end
          expect(@idb.type.to_i).to eq(PcapNG::IDB_TYPE.to_i)
          expect(@idb.block_len.to_i).to eq(32)
          expect(@idb.link_type.to_i).to eq(PcapNG::LINKTYPE_ETHERNET)
          expect(@idb.snaplen.to_i).to eq(0xffff)
          expect(@idb.has_options?).to be(true)
        end
      end
    end

    describe EPB do

      before(:each) { @epb = EPB.new }

      it 'should have correct initialization values' do
        expect(@epb).to be_a(EPB)
        expect(@epb.endian).to eq(:little)
        expect(@epb.type.to_i).to eq(PcapNG::EPB_TYPE.to_i)
        expect(@epb.interface_id.to_i).to eq(0)
        expect(@epb.tsh.to_i).to eq(0)
        expect(@epb.tsl.to_i).to eq(0)
        expect(@epb.cap_len.to_i).to eq(0)
        expect(@epb.orig_len.to_i).to eq(0)
        expect(@epb.block_len.to_i).to eq(EPB::MIN_SIZE)
        expect(@epb.block_len2).to eq(@epb.block_len)
      end

      context 'when reading' do
        it 'should accept a String' do
          str = ::File.read(::File.join(__dir__, '..', 'test', 'sample.pcapng'))[84, 112]
          expect { @epb.read(str) }.to_not raise_error
          expect(@epb.type.to_i).to eq(PcapNG::EPB_TYPE.to_i)
          expect(@epb.block_len.to_i).to eq(112)
          expect(@epb.interface_id.to_i).to eq(0)
          expect(@epb.tsh.to_i).to eq(0x475ad)
          expect(@epb.tsl.to_i).to eq(0xd392be6a)
          expect(@epb.cap_len.to_i).to eq(78)
          expect(@epb.orig_len.to_i).to eq(@epb.cap_len.to_i)
          expect(@epb.has_options?).to be(true)
        end

        it 'should accept an IO' do
          ::File.open(::File.join(__dir__, '..', 'test', 'sample.pcapng')) do |f|
            f.seek(84, :CUR)
            @epb.read f
          end
          expect(@epb.type.to_i).to eq(PcapNG::EPB_TYPE.to_i)
          expect(@epb.block_len.to_i).to eq(112)
          expect(@epb.interface_id.to_i).to eq(0)
          expect(@epb.tsh.to_i).to eq(0x475ad)
          expect(@epb.tsl.to_i).to eq(0xd392be6a)
          expect(@epb.cap_len.to_i).to eq(78)
          expect(@epb.orig_len.to_i).to eq(@epb.cap_len.to_i)
          expect(@epb.has_options?).to be(true)
        end
      end
    end

    describe File do

      before(:all) { @file = ::File.join(__dir__, '..', 'test', 'sample.pcapng') }
      before(:each) { @pcapng = File.new }

      context '#read' do
        it 'reads a Pcap-NG file' do
          @pcapng.read ::File.join(__dir__, '..', 'test', 'sample.pcapng')
          expect(@pcapng.sections.size).to eq(1)

          expect(@pcapng.sections.first.interfaces.size).to eq(1)
          intf = @pcapng.sections.first.interfaces.first
          expect(intf.section).to eq(@pcapng.sections.first)

          expect(intf.packets.size).to eq(11)
          packet = intf.packets.first
          expect(packet.interface).to eq(intf)
        end

        it 'yields xPB object per read packet' do
          idx = 0
          @pcapng.read(@file) do |pkt|
            expect(pkt).to be_a(@Pcapng::EPB)
            idx += 1
          end
          expect(idx).to eq(11)
        end
      end

      context '#read_packets' do
        before(:all) do
          @expected = [UDPPacket] * 2 + [ICMPPacket] * 3 + [ARPPacket] * 2 +
            [TCPPacket] * 3 + [ICMPPacket]
        end

        it 'returns an array of Packets' do
          packets = @pcapng.read_packets(@file)
          expect(packets.map(&:class)).to eq(@expected)

          icmp = packets[2]
          expect(icmp.ip_saddr).to eq('192.168.1.105')
          expect(icmp.ip_daddr).to eq('216.75.1.230')
          expect(icmp.icmp_type).to eq(8)
          expect(icmp.icmp_code).to eq(0)
        end

        it 'yields Packet object per read packet' do
          idx = 0
          @pcapng.read_packets(@file) do |pkt|
            expect(pkt).to be_a(@expected[idx])
            idx += 1
          end
          expect(idx).to eq(11)
        end
      end
    end

  end
end
