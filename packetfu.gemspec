require 'rake'

Gem::Specification.new do |s|
  s.name        = 'packetfu'
  s.version     = '1.1.9'
  s.authors     = ['Tod Beardsley']
  s.email       = 'todb@packetfu.com'
  s.summary     = 'PacketFu is a mid-level packet manipulation library.'
  s.homepage    = 'https://github.com/todb/packetfu'
  s.description = %q{PacketFu is a mid-level packet manipulation library for Ruby. With it, users can read, parse, and write network packets with the level of ease and fun they expect from Ruby. Note that this gem does not automatically require pcaprub, since users may install pcaprub through non-gem means.}
  s.files       = `git ls-files`.split($/)
  s.license     = 'BSD'

  s.add_development_dependency('pcaprub', '>= 0.9.2')
  s.add_development_dependency('rspec',   '>= 2.6.2')
  s.add_development_dependency('sdoc',    '>= 0.2.0')

  s.extra_rdoc_files  = %w[.document README.rdoc]
  s.test_files        = (s.files & (Dir['spec/**/*_spec.rb'] + Dir['test/test_*.rb']) )
  s.rubyforge_project = 'packetfu'
end
