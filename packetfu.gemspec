require 'rake'

Gem::Specification.new do |s|
  s.name = %q{packetfu}
  s.version = "1.0.3.pre"
  s.date = %q{2011-05-22}
  s.authors = ["Tod Beardsley"]
  s.email = %q{todb@planb-security.net}
  s.summary = %q{PacketFu is a mid-level packet manipulation library.}
  s.homepage = %q{http://code.google.com/p/packetfu/}
  s.description = %q{PacketFu is a mid-level packet manipulation library for Ruby. With it, users can read, parse, and write network packets with the level of ease and fun they expect from Ruby. Note that this gem does not automatically require pcaprub, since users may install pcaprub through non-gem means.}
  s.files = FileList["lib/**/*.rb", "CHANGES", "INSTALL", "LICENSE", "README", ".document"]
  s.files << Dir['[A-Z]*'] + Dir["test/**/*"] + Dir["examples/**/*"]
  s.files.reject! {|f| f.match(/\.svn|~$/)}
  s.add_development_dependency('pcaprub',">= 0.9.2")
  s.add_development_dependency('rspec')
  s.extra_rdoc_files = %w{README INSTALL .document}
  s.test_files = Dir.glob("test/test_*.rb")
  s.rubyforge_project = "packetfu"
end
