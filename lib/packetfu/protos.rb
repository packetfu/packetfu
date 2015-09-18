# Picks up all the protocols defined in the protos subdirectory
path = File.expand_path("lib/packetfu/protos/*.rb")
Dir.glob(path).each {|file| require file}
