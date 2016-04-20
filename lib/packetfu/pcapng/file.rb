require_relative 'shb'

module PacketFu
  module PcapNG

    # PcapNG::File is a comple Pcap-NG file handler.
    class File
      attr_accessor :sections

      def initialize
        @sections = []
      end

      # Read a given file and analyze it.
      # If given a block, it will yield PcapNG::EPB or PcapNG::SPB objects.
      # This is the only way to get packet timestamps.
      def read(fname, &blk)
        unless ::File.readable?(fname)
          raise ArgumentError, "cannot read file #{fname}"
        end

        ::File.open(fname, 'rb') do |f|
          while !f.eof? do
            parse_section(f)
          end
        end

        if blk
          count = 0
          @sections.each do |section|
            section.interfaces.each do |intf|
              intf.packets.each { |pkt| count += 1; yield pkt }
            end
          end
          count
        end
      end

      # Give an array of parsed packets (raw data from packets).
      # If a block is given, yield raw packet data from the given file.
      def read_packet_bytes(fname, &blk)
        count = 0
        packets = [] unless blk

        read(fname) do |packet|
          if blk
            count += 1
            yield packet.data.to_s
          else
            packets << packet.data.to_s
          end
        end

        blk ? count : packets
      end

      # Return an array of parsed packets.
      # If a block is given, yield parsed packets from the given file.
      def read_packets(fname, &blk)
        count = 0
        packets = [] unless blk

        read_packet_bytes(fname) do |packet|
          if blk
            count += 1
            yield Packet.parse(packet)
          else
            packets << Packet.parse(packet)
          end
        end

        blk ? count : packets
      end


      private

      def parse_section(io)
        shb = SHB.new
        type = StructFu::Int32.new(0, shb.endian).read(io.read(4))
        io.seek(-4, :CUR)
        shb = parse(type, io, shb)
        raise InvalidFileError, 'no Section header found' unless shb.is_a?(SHB)

        if shb.section_len.to_i != 0xffffffffffffffff
          # Section length is defined
          section = StringIO.new(io.read(shb.section_len.to_i))
          while !section.eof? do
            shb = @sections.last
            type = StructFu::Int32.new(0, shb.endian).read(section.read(4))
            section.seek(-4, :CUR)
            block = parse(type, section, shb)
          end
        else
          # section length is undefined
          while !io.eof?
            shb = @sections.last
            type = StructFu::Int32.new(0, shb.endian).read(io.read(4))
            io.seek(-4, :CUR)
            block = parse(type, io, shb)
          end
        end
      end

      def parse(type, io, shb)
        types = PcapNG.constants(false).select { |c| c.to_s =~ /_TYPE/ }.
          map { |c| [PcapNG.const_get(c).to_i, c] }
        types = Hash[types]

        if types.has_key?(type.to_i)
          klass = PcapNG.const_get(types[type.to_i].to_s.gsub(/_TYPE/, '').to_sym)
          block = klass.new(endian: shb.endian)
        else
          block = UnknownBlock.new(endian: shb.endian)
        end

        classify_block shb, block
        block.read(io)
      end

      def classify_block(shb, block)
        case block
        when SHB
          @sections << block
        when IDB
          shb << block
          block.section = shb
        when EPB
          shb.interfaces[block.interface_id.to_i] << block
          block.interface = shb.interfaces[block.interface_id.to_i]
        #when SPB
        #  shb.interfaces[0] << block
        #  block.interface = shb.interfaces[0]
        end
      end

    end

  end
end
