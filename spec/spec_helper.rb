require 'bundler/setup'
require 'puppet-lint'
require 'puppet-lint-security-plugins'

PuppetLint::Plugins.load_spec_helper
