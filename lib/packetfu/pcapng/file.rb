require_relative 'shb'

module PacketFu
  module PcapNG

    # PcapNG::File is a comple Pcap-NG file handler.
    class File
      attr_accessor :sections

      def initialize
        @sections = []
      end

      def read(fname, &block)
        unless ::File.readable?(fname)
          raise ArgumentError, "cannot read file #{fname}"
        end

        has_section = false
        ::File.open(fname, 'rb') do |f|
          while !f.eof? do
            parse_section(f)
          end
        end
      end

      def read_packet_bytes(fname, &block)
        count = 0
        packets = [] unless block

        read(fname) do |packet|
          if block
            count += 1
            yield packet.data.to_s
          else
            packets << packet.data.to_s
          end
        end

        block ? count : packets
      end


      private

      def parse_section(io)
        endian = :little
        type = StructFu::Int32.new(0, endian).read(io.read(4))
        io.seek(-4, :CUR)
        shb = parse(type, io, endian)
        raise InvalidFileError, 'no Section header found' unless shb.is_a?(SHB)

        @sections << shb

        if shb.section_len.to_i != 0xffffffffffffffff
          # Section length is defined
          section = StringIO.new(io.read(shb.section_len.to_i))
          while !section.eof? do
            shb = @sections.last
            type = StructFu::Int32.new(0, endian).read(section.read(4))
            section.seek(-4, :CUR)
            block = parse(type, section, shb.endian)

            classify_block shb, block
          end
        else
          # section length is undefined
          while !io.eof?
            shb = @sections.last
            type = StructFu::Int32.new(0, endian).read(io.read(4))
            io.seek(-4, :CUR)
            block = parse(type, io, shb.endian)

            classify_block shb, block
          end
        end
      end

      def parse(type, io, endian)
        types = PcapNG.constants(false).select { |c| c.to_s =~ /_TYPE/ }.
          map { |c| [PcapNG.const_get(c).to_i, c] }
        types = Hash[types]

        if types.has_key?(type.to_i)
          klass = PcapNG.const_get(types[type.to_i].to_s.gsub(/_TYPE/, '').to_sym)
          block = klass.new(endian: endian)
        else
          block = UnknownBlock.new(endian: endian)
        end
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
