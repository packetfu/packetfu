# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/tcp'
require 'packetfu/protos/icmp'
require 'packetfu/config'
require 'packetfu/pcap'
require 'packetfu/utils'
require 'tempfile'

include PacketFu

describe Capture do

  if Process.uid != 0
    warn "Not running as root, PacketFu::Capture capabilities that require root will be skipped"
  end

  context "when creating an object from scratch" do
    before :each do
      @capture = PacketFu::Capture.new
    end

    it "should have sane defaults" do
      expect(@capture.array).to be_kind_of(Array)
      expect(@capture.stream).to be_kind_of(Array)
      expect(@capture.iface).to be_kind_of(String)
      expect(@capture.snaplen).to eql(65535)
      expect(@capture.promisc).to eql(false)
      expect(@capture.timeout).to eql(1)

      # Requires root/sudo to get this...
      if Process.uid == 0
        expect(@capture.filter).to eql(nil)
      else
        expect{@capture.filter}.to raise_error(RuntimeError)
      end
    end

    it "should allow creating a capture object with non-std attributes" do
      # Can only run this if we're root
      if Process.uid == 0
        options = {
          :iface => PacketFu::Utils::default_int,
          :snaplen => 0xfffe,
          :promisc => true,
          :timeout => 5,
          :filter => "not port 22",
        }
        @capture = PacketFu::Capture.new(options)

        expect(@capture.array).to be_kind_of(Array)
        expect(@capture.stream).to be_kind_of(PCAPRUB::Pcap)
        expect(@capture.iface).to eql(options[:iface])
        expect(@capture.snaplen).to eql(options[:snaplen])
        expect(@capture.promisc).to eql(options[:promisc])
        expect(@capture.timeout).to eql(options[:timeout])
        expect(@capture.filter).to eql(options[:filter])
        expect(@capture.bpf).to eql(options[:filter])
      end
    end
  end

  context "when capturing traffic on the wire" do
    # Can only run this if we're root
    if Process.uid == 0
      it "should capture an ICMP echo request from the wire" do
        daddr = PacketFu::Utils.rand_routable_daddr.to_s

        def do_capture_test(daddr)
          begin
            Timeout::timeout(3) {
              cap = PacketFu::Capture.new(:iface => PacketFu::Utils::default_int, :start => true)
              cap.stream.each do |p|
                pkt = PacketFu::Packet.parse p
                next unless pkt.is_icmp?

                if pkt.ip_daddr == daddr and pkt.icmp_type == 8
                  return true
                end
              end
            }
          rescue Timeout::Error
            return false
          end
        end

        capture_thread = Thread.new { expect(do_capture_test(daddr)).to eql(true) }
        %x{ping -c 1 #{daddr}}
        capture_thread.join
      end

      it "should capture only capture ICMP echo requests we ask for from the wire" do
        daddr = PacketFu::Utils.rand_routable_daddr.to_s
        daddr2 = PacketFu::Utils.rand_routable_daddr.to_s

        def do_bpf_capture_test(daddr, daddr2)
          count = 0
          valid_icmp = false
          invalid_icmp = false

          begin
            Timeout::timeout(3) {
              cap = PacketFu::Capture.new(:iface => PacketFu::Utils::default_int, :start => true, :filter => "icmp and dst host #{daddr}")
              cap.stream.each do |p|
                pkt = PacketFu::Packet.parse p
                next unless pkt.is_icmp?
                count += 1

                if pkt.ip_daddr == daddr and pkt.icmp_type == 8
                  valid_icmp = true
                elsif pkt.ip_daddr == daddr2 and pkt.icmp_type == 8
                  invalid_icmp = true
                end
              end
            }
          rescue Timeout::Error
            ### do nothing, we need to wait for the timeout anyways
          end

          if count == 1 && valid_icmp == true && invalid_icmp == false
            return true
          else
            return false
          end
        end

        capture_thread = Thread.new { expect(do_bpf_capture_test(daddr,daddr2)).to eql(true) }
        %x{ping -c 1 #{daddr}}
        %x{ping -c 1 #{daddr2}}
        capture_thread.join
      end
    end
  end
end