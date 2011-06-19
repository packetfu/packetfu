require 'rake'

Gem::Specification.new do |s|
  s.name = %q{packetfu}
  s.version = "1.1.1"
  s.date = %q{2011-06-15}
  s.authors = ["Tod Beardsley"]
  s.email = %q{todb@planb-security.net}
  s.summary = %q{PacketFu is a mid-level packet manipulation library.}
  s.homepage = %q{https://github.com/todb/packetfu}
  s.description = %q{PacketFu is a mid-level packet manipulation library for Ruby. With it, users can read, parse, and write network packets with the level of ease and fun they expect from Ruby. Note that this gem does not automatically require pcaprub, since users may install pcaprub through non-gem means.}
  s.files = `git ls-files`.split($/)
	s.has_rdoc = true # Use sdoc, though, it's nicer.
	s.license = 'BSD' 
  s.add_development_dependency('pcaprub',">= 0.9.2")
  s.add_development_dependency('rspec',">= 2.6.2")
  s.add_development_dependency('sdoc',">= 0.2.0")
  s.extra_rdoc_files = %w{README .document}
  s.test_files = (s.files & Dir["test/test_*.rb"])
  s.rubyforge_project = "packetfu"
end
