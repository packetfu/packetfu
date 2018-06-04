# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/tcp/header'
require 'packetfu/protos/tcp/mixin'

require 'packetfu/protos/ip/header'
require 'packetfu/protos/ip/mixin'

require 'packetfu/protos/ipv6/header'
require 'packetfu/protos/ipv6/mixin'

module PacketFu
  # TCPPacket is used to construct TCP packets. They contain an EthHeader, an IPHeader, and a TCPHeader.
  #
  # == Example
  #
  #    tcp_pkt = PacketFu::TCPPacket.new
  #    tcp_pkt.tcp_flags.syn=1
  #    tcp_pkt.tcp_dst=80
  #    tcp_pkt.tcp_win=5840
  #    tcp_pkt.tcp_options="mss:1460,sack.ok,ts:#{rand(0xffffffff)};0,nop,ws:7"
  #
  #    tcp_pkt.ip_saddr=[rand(0xff),rand(0xff),rand(0xff),rand(0xff)].join('.')
  #    tcp_pkt.ip_daddr=[rand(0xff),rand(0xff),rand(0xff),rand(0xff)].join('.')
  #
  #    tcp_pkt.recalc
  #    tcp_pkt.to_f('/tmp/tcp.pcap')
  #
  #    tcp6_pkt = PacketFu::TCPPacket.new(:on_ipv6 => true)
  #    tcp6_pkt.tcp_flags.syn=1
  #    tcp6_pkt.tcp_dst=80
  #    tcp6_pkt.tcp_win=5840
  #    tcp6_pkt.tcp_options="mss:1460,sack.ok,ts:#{rand(0xffffffff)};0,nop,ws:7"
  #    tcp6_pkt.ipv6_saddr="4::1"
  #    tcp6_pkt.ipv6_daddr="12:3::4567"
  #    tcp6_pkt.recalc
  #    tcp6_pkt.to_f('/tmp/udp.pcap')
  #
  # == Parameters
  #  :eth
  #    A pre-generated EthHeader object.
  #  :ip
  #    A pre-generated IPHeader object.
  #  :flavor
  #    TODO: Sets the "flavor" of the TCP packet. This will include TCP options and the initial window
  #    size, per stack. There is a lot of variety here, and it's one of the most useful methods to
  #    remotely fingerprint devices. :flavor will span both ip and tcp for consistency.
  #   :type
  #    TODO: Set up particular types of packets (syn, psh_ack, rst, etc). This can change the initial flavor.
  #  :config
  #   A hash of return address details, often the output of Utils.whoami?
  class TCPPacket < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPHeaderMixin
    include ::PacketFu::IPv6HeaderMixin
    include ::PacketFu::TCPHeaderMixin

    attr_accessor :eth_header, :ip_header, :ipv6_header, :tcp_header

    def self.can_parse?(str)
      return false unless str.size >= 54
      return false unless EthPacket.can_parse? str
      if IPPacket.can_parse? str
        return true if str[23,1] == "\x06"
      elsif IPv6Packet.can_parse? str
        return true if str[20,1] == "\x06"
      end
      return false
    end

    def read(str=nil, args={})
      super
      # Strip off any extra data, if we are asked to do so.
      if args[:strip]
        tcp_body_len = self.ip_len - self.ip_hlen - (self.tcp_hlen * 4)
        @tcp_header.body.read(@tcp_header.body.to_s[0,tcp_body_len])
        tcp_calc_sum
        @ip_header.ip_recalc
      end
      self
    end

    def initialize(args={})
      if args[:on_ipv6] or args[:ipv6]
        @eth_header = EthHeader.new(args.merge(:eth_proto => 0x86dd)).read(args[:eth])
        @ipv6_header = IPv6Header.new(args).read(args[:ipv6])
        @tcp_header = TCPHeader.new(args).read(args[:tcp])

        @ipv6_header.body = @tcp_header
        @eth_header.body = @ipv6_header
        @headers = [@eth_header, @ipv6_header, @tcp_header]

        @ipv6_header.ipv6_next = 0x06
      else
        @eth_header = EthHeader.new(args.merge(:eth_proto => 0x0800)).read(args[:eth])
        @ip_header = IPHeader.new(args).read(args[:ip])
        @tcp_header = TCPHeader.new(args).read(args[:tcp])

        @ip_header.body = @tcp_header
        @eth_header.body = @ip_header
        @headers = [@eth_header, @ip_header, @tcp_header]

        @ip_header.ip_proto = 0x06
      end
      @tcp_header.flavor = args[:flavor].to_s.downcase

      super
      if args[:flavor]
        tcp_calc_flavor(@tcp_header.flavor)
      else
        tcp_calc_sum
      end
    end

    # Sets the correct flavor for TCP Packets. Recognized flavors are:
    #   windows, linux, freebsd
    def tcp_calc_flavor(str)
      ts_val = Time.now.to_i + rand(0x4fffffff)
      ts_sec = rand(0xffffff)
      case @tcp_header.flavor = str.to_s.downcase
      when "windows" # WinXP's default syn
        @tcp_header.tcp_win = 0x4000
        @tcp_header.tcp_options="MSS:1460,NOP,NOP,SACKOK"
        @tcp_header.tcp_src = rand(5000 - 1026) + 1026
        @ip_header.ip_ttl = 64
      when "linux" # Ubuntu Linux 2.6.24-19-generic default syn
        @tcp_header.tcp_win = 5840
        @tcp_header.tcp_options="MSS:1460,SACKOK,TS:#{ts_val};0,NOP,WS:7"
        @tcp_header.tcp_src = rand(61_000 - 32_000) + 32_000
        @ip_header.ip_ttl = 64
      when "freebsd" # Freebsd
        @tcp_header.tcp_win = 0xffff
        @tcp_header.tcp_options="MSS:1460,NOP,WS:3,NOP,NOP,TS:#{ts_val};#{ts_sec},SACKOK,EOL,EOL"
        @ip_header.ip_ttl = 64
      else
        @tcp_header.tcp_options="MSS:1460,NOP,NOP,SACKOK"
      end
      tcp_calc_sum
    end

    # tcp_calc_sum() computes the TCP checksum, and is called upon intialization. It usually
    # should be called just prior to dropping packets to a file or on the wire.
    #--
    # This is /not/ delegated down to @tcp_header since we need info
    # from the IP header, too.
    #++
    def tcp_calc_sum
      if @ipv6_header
        checksum = ipv6_calc_sum_on_addr
        tcp_len = ipv6_len
      else
        checksum = ip_calc_sum_on_addr
        tcp_len = ip_len.to_i - ((ip_hl.to_i) * 4)
      end

      checksum += 0x06 # TCP Protocol.
      checksum += tcp_len
      checksum += tcp_src
      checksum += tcp_dst
      checksum += (tcp_seq.to_i >> 16)
      checksum += (tcp_seq.to_i & 0xffff)
      checksum += (tcp_ack.to_i >> 16)
      checksum += (tcp_ack.to_i & 0xffff)
      checksum += ((tcp_hlen << 12) + 
                   (tcp_reserved << 9) + 
                   (tcp_ecn.to_i << 6) + 
                   tcp_flags.to_i
                  )
      checksum += tcp_win
      checksum += tcp_urg

      chk_tcp_opts = (tcp_opts.to_s.size % 2 == 0 ? tcp_opts.to_s : tcp_opts.to_s + "\x00") 
      chk_tcp_opts.unpack("n*").each {|x| checksum = checksum + x }
      if (tcp_len - (tcp_hlen * 4)) >= 0
        real_tcp_payload = payload[0, (tcp_len - (tcp_hlen * 4))] # Can't forget those pesky FCSes!
      else
        real_tcp_payload = payload # Something's amiss here so don't bother figuring out where the real payload is.
      end
      chk_payload = (real_tcp_payload.size % 2 == 0 ? real_tcp_payload : real_tcp_payload + "\x00") # Null pad if it's odd.
      chk_payload.unpack("n*").each {|x| checksum = checksum+x }
      checksum = checksum % 0xffff
      checksum = 0xffff - checksum
      checksum == 0 ? 0xffff : checksum
      @tcp_header.tcp_sum = checksum
    end

    # Recalculates various fields of the TCP packet.
    #
    # ==== Parameters
    #
    #   :all
    #     Recomputes all calculated fields.
    #   :tcp_sum
    #     Recomputes the TCP checksum.
    #   :tcp_hlen
    #     Recomputes the TCP header length. Useful after options are added.
    def tcp_recalc(arg=:all)
      case arg
      when :tcp_sum
        tcp_calc_sum
      when :tcp_hlen
        @tcp_header.tcp_recalc :tcp_hlen
      when :all
        @tcp_header.tcp_recalc :all
        tcp_calc_sum
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # TCP packets are denoted by a "T  ", followed by size,
    # source and dest information, packet flags, sequence
    # number, and IPID.
    def peek_format
      if ipv6?
        peek_data = ["6T "]
        peek_data << "%-5d" % self.to_s.size
        peek_data << "%-31s" % "#{self.ipv6_saddr}:#{self.tcp_src}"
        peek_data << "->"
        peek_data << "%31s" % "#{self.ipv6_daddr}:#{self.tcp_dst}"
      else
        peek_data = ["T  "]
        peek_data << "%-5d" % self.to_s.size
        peek_data << "%-21s" % "#{self.ip_saddr}:#{self.tcp_src}"
        peek_data << "->"
        peek_data << "%21s" % "#{self.ip_daddr}:#{self.tcp_dst}"
      end
      flags = ' ['
      flags << self.tcp_flags_dotmap
      flags << '] '
      peek_data << flags
      peek_data << "S:"
      peek_data << "%08x" % self.tcp_seq
      unless ipv6?
        peek_data << "|I:"
        peek_data << "%04x" % self.ip_id
      end
      peek_data.join
    end

  end

end
