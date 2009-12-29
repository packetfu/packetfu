#!/usr/bin/env ruby
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'
include PacketFu

@p = PcapFile.new
