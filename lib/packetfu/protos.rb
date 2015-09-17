# Picks up all the protocols defined in the protos subdirectory
Dir.glob("packetfu/protos").each do |file|
  next unless file[/\.rb$/]
  require File.expand_path(file)
end
