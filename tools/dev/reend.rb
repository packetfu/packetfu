#!/usr/bin/env ruby
# -*- coding: binary -*-

# Replace trailling spaces with nothing.
# I'm sure there's a sed/awk/perl oneliner that's
# a million times better but this is more readable for me.

require 'fileutils'
require 'find'

dir = ARGV[0] || "."
raise ArgumentError, "Need a filename or directory" unless (dir and File.readable? dir)

Find.find(dir) do |infile|
  next unless File.file? infile
  next unless infile =~ /rb$/
outfile = infile
backup = "#{infile}.noend"
FileUtils.cp infile, backup

data = File.open(infile, "rb") {|f| f.read f.stat.size}
fixed = []
data.each_line do |line|
  fixed << line
  next unless line =~ /[\x20\x09]$/
  fixed[-1] = line.sub(/[\x20\x09]+$/, '')
end

fh = File.open(outfile, "wb")
fh.write fixed.join
fh.close
puts "Reended #{fh.path}"
end
