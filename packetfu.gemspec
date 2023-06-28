require './lib/packetfu/version'

Gem::Specification.new do |s|
  s.name        = 'packetfu'
  s.version     = PacketFu::VERSION
  s.authors     = ['Tod Beardsley', 'Jonathan Claudius']
  s.email       = ['todb@packetfu.com', 'claudijd@yahoo.com']
  s.summary     = 'PacketFu is a mid-level packet manipulation library.'
  s.homepage    = 'https://github.com/packetfu/packetfu'
  s.description = %q{
    PacketFu is a mid-level packet manipulation library for Ruby. With
    it, users can read, parse, and write network packets with the level of
    ease and fun they expect from Ruby.
  }
  s.files       = `git ls-files`.split($/)
  s.license     = 'BSD-3-Clause'
  s.required_ruby_version = '>= 2.7.0'
  s.add_dependency('pcaprub', '~> 0.13.1')
  s.add_development_dependency('rake')
  s.add_development_dependency('rspec', '~> 3.0')
  s.add_development_dependency('rspec-its', '~> 1.2')
  s.add_development_dependency('sdoc', '~> 0.4')
  s.add_development_dependency('pry-byebug')
  s.add_development_dependency('coveralls', '~> 0.8')

  s.extra_rdoc_files  = %w[.document README.md]
  s.test_files        = (s.files & (Dir['spec/**/*_spec.rb'] + Dir['test/test_*.rb']) )

  s.cert_chain = ['certs/todb.pem']
  s.signing_key = File.expand_path("~/.ssh/gem-private_key.pem") if $0 =~ /gem\z/
end
