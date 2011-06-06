require 'rake'

Gem::Specification.new do |s|
  s.name = %q{packetfu}
  s.version = "1.0.5.pre"
  s.date = %q{2011-06-06}
  s.authors = ["Tod Beardsley"]
  s.email = %q{todb@planb-security.net}
  s.summary = %q{PacketFu is a mid-level packet manipulation library.}
  s.homepage = %q{http://code.google.com/p/packetfu/}
  s.description = %q{PacketFu is a mid-level packet manipulation library for Ruby. With it, users can read, parse, and write network packets with the level of ease and fun they expect from Ruby. Note that this gem does not automatically require pcaprub, since users may install pcaprub through non-gem means.}
  s.files = FileList["lib/**/*.rb", "INSTALL", "LICENSE", "README", ".document"]
  s.files << Dir['[A-Z]*'] + Dir["test/**/*"] + Dir["examples/**/*"]
  s.files.reject! {|f| f.match(/\.svn|~$/)}
	s.has_rdoc = true # Use sdoc, though, it's nicer.
	s.license = 'BSD' 
  s.add_development_dependency('pcaprub',">= 0.9.2")
	s.requirements << 'sdoc, for generating local documentation'
	s.requirements << 'rspec, v2.6.2 or later, for testing'
	s.requirements << 'pcaprub v0.9.2 or later, for packet capture/inject'
  s.extra_rdoc_files = %w{README INSTALL .document}
  s.test_files = Dir.glob("test/test_*.rb")
  s.rubyforge_project = "packetfu"
end
