# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/ip/header'
require 'packetfu/protos/ip/mixin'

require 'packetfu/protos/udp/header'
require 'packetfu/protos/udp/mixin'

module PacketFu

  # UDPPacket is used to construct UDP Packets. They contain an EthHeader, an IPHeader, and a UDPHeader.
  #
  # == Example
  #
  #   udp_pkt = PacketFu::UDPPacket.new
  #   udp_pkt.udp_src=rand(0xffff-1024) + 1024
  #   udp_pkt.udp_dst=53
  # 
  #   udp_pkt.ip_saddr="1.2.3.4"
  #   udp_pkt.ip_daddr="10.20.30.40"
  #
  #   udp_pkt.recalc
  #   udp_pkt.to_f('/tmp/udp.pcap')
  #
  # == Parameters
  #
  #  :eth
  #    A pre-generated EthHeader object.
  #  :ip
  #    A pre-generated IPHeader object.
  #  :flavor
  #    TODO: Sets the "flavor" of the UDP packet. UDP packets don't tend have a lot of
  #    flavor, but their underlying ip headers do.
  #  :config
  #   A hash of return address details, often the output of Utils.whoami?
  class UDPPacket < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPHeaderMixin
    include ::PacketFu::UDPHeaderMixin

    attr_accessor :eth_header, :ip_header, :udp_header

    def self.can_parse?(str)
      return false unless str.size >= 28
      return false unless EthPacket.can_parse? str
      return false unless IPPacket.can_parse? str
      return false unless str[23,1] == "\x11"
      return true
    end

    def read(str=nil, args={})
      raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
      @eth_header.read(str)
      if args[:strip]
        udp_body_len = self.ip_len - self.ip_hlen - 8
        @udp_header.body.read(@udp_header.body.to_s[0,udp_body_len])
      end
      super(args)
      self
    end

    def initialize(args={})
      @eth_header = EthHeader.new(args).read(args[:eth])
      @ip_header = IPHeader.new(args).read(args[:ip])
      @ip_header.ip_proto=0x11
      @udp_header = UDPHeader.new(args).read(args[:icmp])
      @ip_header.body = @udp_header
      @eth_header.body = @ip_header
      @headers = [@eth_header, @ip_header, @udp_header]
      super
      udp_calc_sum
    end

    # udp_calc_sum() computes the UDP checksum, and is called upon intialization. 
    # It usually should be called just prior to dropping packets to a file or on the wire. 
    def udp_calc_sum
      # This is /not/ delegated down to @udp_header since we need info
      # from the IP header, too.
      checksum = (ip_src.to_i >> 16)
      checksum += (ip_src.to_i & 0xffff)
      checksum += (ip_dst.to_i >> 16)
      checksum += (ip_dst.to_i & 0xffff)
      checksum += 0x11
      checksum += udp_len.to_i
      checksum += udp_src.to_i
      checksum += udp_dst.to_i
      checksum += udp_len.to_i
      if udp_len.to_i >= 8
        # For IP trailers. This isn't very reliable. :/
        real_udp_payload = payload.to_s[0,(udp_len.to_i-8)] 
      else
        # I'm not going to mess with this right now.
        real_udp_payload = payload 
      end
      chk_payload = (real_udp_payload.size % 2 == 0 ? real_udp_payload : real_udp_payload + "\x00")
      chk_payload.unpack("n*").each {|x| checksum = checksum+x}
      checksum = checksum % 0xffff
      checksum = 0xffff - checksum
      checksum == 0 ? 0xffff : checksum
      @udp_header.udp_sum = checksum
    end

    # udp_recalc() recalculates various fields of the UDP packet. Valid arguments are:
    #
    #   :all
    #     Recomputes all calculated fields.
    #   :udp_sum
    #     Recomputes the UDP checksum.
    #   :udp_len
    #     Recomputes the UDP length.
    def udp_recalc(args=:all)
      case args
      when :udp_len
        @udp_header.udp_recalc
      when :udp_sum
        udp_calc_sum
      when :all
        @udp_header.udp_recalc
        udp_calc_sum
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # Peek provides summary data on packet contents.
    def peek_format
      peek_data = ["U  "]
      peek_data << "%-5d" % self.to_s.size
      peek_data << "%-21s" % "#{self.ip_saddr}:#{self.udp_sport}"
      peek_data << "->"
      peek_data << "%21s" % "#{self.ip_daddr}:#{self.udp_dport}"
      peek_data << "%23s" % "I:"
      peek_data << "%04x" % self.ip_id
      peek_data.join
    end

  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
