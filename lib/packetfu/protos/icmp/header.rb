# -*- coding: binary -*-
module PacketFu
  # ICMPHeader is a complete ICMP struct, used in ICMPPacket. ICMP is 
  # typically used for network administration and connectivity testing.
  #
  # For more on ICMP packets, see 
  # http://www.networksorcery.com/enp/protocol/icmp.htm
  # 
  # ==== Header Definition
  #
  #   Int8    :icmp_type                        # Type
  #   Int8    :icmp_code                        # Code
  #   Int16   :icmp_sum    Default: calculated  # Checksum
  #   String  :body
  class ICMPHeader < Struct.new(:icmp_type, :icmp_code, :icmp_sum, :body)

    include StructFu

    def initialize(args={})
      super(
        Int8.new(args[:icmp_type]),
        Int8.new(args[:icmp_code]),
        Int16.new(args[:icmp_sum] || icmp_calc_sum),
        StructFu::String.new.read(args[:body])
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
      self[:icmp_type].read(str[0,1])
      self[:icmp_code].read(str[1,1])
      self[:icmp_sum].read(str[2,2])
      self[:body].read(str[4,str.size])
      self
    end

    # Setter for the type.
    def icmp_type=(i); typecast i; end
    # Getter for the type.
    def icmp_type; self[:icmp_type].to_i; end
    # Setter for the code.
    def icmp_code=(i); typecast i; end
    # Getter for the code.
    def icmp_code; self[:icmp_code].to_i; end
    # Setter for the checksum. Note, this is calculated automatically with 
    # icmp_calc_sum.
    def icmp_sum=(i); typecast i; end
    # Getter for the checksum.
    def icmp_sum; self[:icmp_sum].to_i; end

    # Calculates and sets the checksum for the object.
    def icmp_calc_sum
      checksum = (icmp_type.to_i << 8)	+ icmp_code.to_i
      chk_body = (body.to_s.size % 2 == 0 ? body.to_s : body.to_s + "\x00")
      if 1.respond_to? :ord
        chk_body.split("").each_slice(2).map { |x| (x[0].ord << 8) + x[1].ord }.each { |y| checksum += y }
      else
        chk_body.split("").each_slice(2).map { |x| (x[0] << 8) + x[1] }.each { |y| checksum += y }
      end
      checksum = checksum % 0xffff
      checksum = 0xffff - checksum
      checksum == 0 ? 0xffff : checksum
    end
    
    # Recalculates the calculatable fields for ICMP.
    def icmp_recalc(arg=:all)
      # How silly is this, you can't intern a symbol in ruby 1.8.7pl72?
      # I'm this close to monkey patching Symbol so you can force it...
      arg = arg.intern if arg.respond_to? :intern
      case arg
      when :icmp_sum
        self.icmp_sum=icmp_calc_sum
      when :all
        self.icmp_sum=icmp_calc_sum
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # Readability aliases

    def icmp_sum_readable
      "0x%04x" % icmp_sum
    end

  end
end
