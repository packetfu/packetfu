#!/usr/bin/env ruby
module StructFu

  def set_endianness(e=nil)
    unless [:little, :big].include? e
      raise ArgumentError, "Unknown endianness for #{self.class}" 
    end
    @int32 = e == :little ? Int32le : Int32be
    @int16 = e == :little ? Int16le : Int16be
    return e
  end

end

module PacketFu

  class PcapHeader < Struct.new(:endian, :magic, :ver_major, :ver_minor,
                                :thiszone, :sigfigs, :snaplen, :network)
    include StructFu

    def initialize(args={})
      set_endianness(args[:endian] ||= :little)
      init_fields(args)
      super(args[:endian], args[:magic], args[:ver_major], 
            args[:ver_minor], args[:thiszone], args[:sigfigs], 
            args[:snaplen], args[:network])
    end
    
    def init_fields(args={})
      args[:magic] ||= @int32.new(0xa1b2c3d4)
      args[:ver_major] ||= @int16.new(2)
      args[:ver_minor] ||= @int16.new(4)
      args[:thiszone] ||= @int32.new(0)
      args[:sigfigs] ||= @int32.new(0)
      args[:snaplen] ||= @int32.new(0xffff)
      args[:network] ||= @int32.new(1)
      return args
    end

    def to_s
      self.to_a[1,7].map {|x| x.to_s}.join
    end

    # TODO: read() should determine endianness and switch accordingly.
    # At the moment, the user needs to know endianness ahead of time
    # (defaults to little). This is a bummer, will fix once I get
    # a hold of a big-endian file to test with (not hard).
    def read(str)
      if str[0,4] == self[:magic].to_s || true # always true for now
        self[:magic].read str[0,4]
        self[:ver_major].read str[4,2]
        self[:ver_minor].read str[6,2]
        self[:thiszone].read str[8,4]
        self[:sigfigs].read str[12,4]
        self[:snaplen].read str[16,4]
        self[:network].read str[20,4]
        self
      end
    end

  end

  class Timestamp < Struct.new(:endian, :sec, :usec)
    include StructFu
    def initialize(args={})
      set_endianness(args[:endian] ||= :little)
      init_fields(args)
      super(args[:endian], args[:sec], args[:usec])
    end

    def init_fields(args={})
      args[:sec] ||= @int32.new(0)
      args[:usec] ||= @int32.new(0)
      return args
    end

    def to_s
      self.to_a[1,2].map {|x| x.to_s}.join
    end

    def read(str)
      self[:sec].read str[0,4]
      self[:usec].read str[4,4]
      self
    end

  end

  class PcapPacket < Struct.new(:endian, :timestamp, :incl_len,
                               :orig_len, :data)
    include StructFu
    def initialize(args={})
      set_endianness(args[:endian] ||= :little)
      init_fields(args)
      super(args[:endian], args[:timestamp], args[:incl_len],
           args[:orig_len], args[:data])
    end

    def init_fields(args={})
      args[:timestamp] ||= Timestamp.new(:endian => args[:endian])
      args[:incl_len] ||= @int32.new(args[:data].sz)
      args[:orig_len] ||= @int32.new(0)
      args[:data] ||= StructFu::String.new
    end

    def to_s
      self.to_a[1,4].map {|x| x.to_s}.join
    end

    def read(str)
      self[:timestamp].read str[0,8]
      self[:incl_len].read str[8,4]
      self[:orig_len].read str[12,4]
      self[:data].read str[16,self[:incl_len].to_i]
      self
    end


  end

end
