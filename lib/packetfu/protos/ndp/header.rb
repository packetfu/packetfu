require 'packetfu/protos/ipv6/header'
require 'packetfu/protos/ipv6/mixin'

module PacketFu

  # NeighborDiscoveryHeader is a complete ICMPv6 struct, used in
  # NDPPacket for Neighbor Advertisment and Neighbor Solicitation.
  #
  # ==== Header Definition
  #   Int8      :ndp_type                        # Type
  #   Int8      :ndp_code                        # Code
  #   Int16     :ndp_sum    Default: calculated  # Checksum
  #   Int32     :ndp_res    Default: 0x0         # Reserved
  #
  class NDPHeader < Struct.new(:ndp_type, :ndp_code, :ndp_sum, :ndp_reserved,
                                :ndp_tgt, :ndp_opt_type, :ndp_opt_len, :body)
    include StructFu

    PROTOCOL_NUMBER = 58
    NEIGHBOR_SOLICITATION_CODE = 135
    NEIGHBOR_ADVERTISEMENT_CODE = 136

    def initialize(args={})
      super(
        Int8.new(args[:ndp_type]),
        Int8.new(args[:ndp_code]),
        Int16.new(args[:ndp_sum]),
        Int32.new(args[:ndp_reserved]),
        AddrIpv6.new.read(args[:ndp_tgt] || ("\x00" * 16)),
        Int8.new(args[:ndp_opt_type]),
        Int8.new(args[:ndp_opt_len])
      )
    end

    # Returns the object in string form.
    def to_s
      self.to_a.map {|x| x.to_s}.join
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      self[:ndp_type].read(str[0,1])
      self[:ndp_code].read(str[1,1])
      self[:ndp_sum].read(str[2,2])
      self[:ndp_reserved].read(str[4,4])
      self[:ndp_tgt].read(str[8,16])
      self[:ndp_opt_type].read(str[24,1])
      self[:ndp_opt_len].read(str[25,1])
      self
    end

    # Setter for the type.
    def ndp_type=(i); typecast i; end
    # Getter for the type.
    def ndp_type; self[:ndp_type].to_i; end
    # Setter for the code.
    def ndp_code=(i); typecast i; end
    # Getter for the code.
    def ndp_code; self[:ndp_code].to_i; end
    # Setter for the checksum. Note, this is calculated automatically with
    # ndp_calc_sum.
    def ndp_sum=(i); typecast i; end
    # Getter for the checksum.
    def ndp_sum; self[:ndp_sum].to_i; end
    # Setter for the reserved.
    def ndp_reserved=(i); typecast i; end
    # Getter for the reserved.
    def ndp_reserved; self[:ndp_reserved].to_i; end
    # Setter for the target address.
    def ndp_tgt=(i); typecast i; end
    # Getter for the target address.
    def ndp_tgt; self[:ndp_tgt].to_i; end
    # Setter for the options type field.
    def ndp_opt_type=(i); typecast i; end
    # Getter for the options type field.
    def ndp_opt_type; self[:ndp_opt_type].to_i; end
    # Setter for the options length.
    def ndp_opt_len=(i); typecast i; end
    # Getter for the options length.
    def ndp_opt_len; self[:ndp_opt_len].to_i; end

    # Get target address in a more readable form.
    def ndp_taddr
        self[:ndp_tgt].to_x
    end

    # Set the target address in a more readable form.
    def ndp_taddr=(str)
        self[:ndp_tgt].read_x(str)
    end

    def ndp_sum_readable
      "0x%04x" % ndp_sum
    end

    alias :ndp_tgt_readable :ndp_taddr

  end
end
