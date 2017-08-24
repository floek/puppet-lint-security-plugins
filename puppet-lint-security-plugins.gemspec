Gem::Specification.new do |spec|
  spec.name        = 'puppet-lint-security-plugins'
  spec.version     = '0.2.0'
  spec.homepage    = 'https://github.com/floek/puppet-lint-security-plugins'
  spec.license     = 'MIT'
  spec.author      = 'Florian Freund'
  spec.email       = 'mail@floek.net'
  spec.files       = Dir[
    'README.md',
    'LICENSE',
    'lib/**/*',
    'spec/**/*',
  ]
  spec.test_files  = Dir['spec/**/*']
  spec.summary     = 'A puppet-lint plugin to check security issues.'
  spec.description = <<-EOF
    Checks puppet manifests for security related problems.
  EOF

  spec.add_dependency             'puppet-lint', '~> 2.0'
  spec.add_development_dependency 'rspec', '~> 3.3'
  spec.add_development_dependency 'rspec-its', '~> 1.0'
  spec.add_development_dependency 'rspec-collection_matchers', '~> 1.0'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'mail'
  spec.add_development_dependency 'yard'
end
