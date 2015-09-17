# Picks up all the protocols defined in the protos subdirectory
Dir.glob("protos/*.rb").each do |file|
  require File.expand_path(file)
end
