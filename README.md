# Puppet-lint-security-plugins

The goal of this project is to identify security issues in your Puppet code. Some basic checks
are implemented, please feel free to contribute.

## Installation

    gem install puppet-lint-security-plugins
    [![Gem Version](https://badge.fury.io/rb/puppet-lint-security-plugins@2x.png)](https://badge.fury.io/rb/puppet-lint-security-plugins)

## Testing your manifests

Just use `puppet-lint`. After installation security checks are enabled by default.

## Implemented tests

At the moment, the following tests have been implemented:

### Puppet Resource Types

 * Must not use `eval` in inline\_templates
 * Must not use setuid bit in `file` resources when owner equals `root`
 * Must not use setgid bit in `file` resources when group equals `root`
 * Must not use mode `777` in `file` resources
 * Should not pin packages to specific version
 * Must not store plaintext passwords in the manifest
 * Must not use password variables in exec
 * Should use range markers (\A,\z,^,$) in regular expressions
 * Must not use class or defined\_type parameters in `exec`
 * Should not use `tidy`with `age` and/or `size` parameter
 * Should not use `tidy` with `match` equals to `*`
 * Should not use `tidy` with `recurse` enabled
 * Must not create non root user with id 0
 * Should not disable services (example: mysql, puppetmaster)

### puppetlabs-apache module

 * Should not use bad ciphers
 * Should enable ssl on any vhost

### puppetlabs-apt module

 * Must use an GPG key in repository definition

### puppetlabs-firewall module

 * Must not use firewall allow rules with source and destination equals `any`
 * Should not use firewall deny rules with source and destination equals `any` (possible deny of service)
 * Must use ips or subnets in source or destination (no dns)
 * Should not block puppetmaster port

### saz/ssh module

 * Must not enable `PermitRootLogin`

### saz/sudo module

 * Must not define sudo to anyone with root permissions

## Reporting bugs or incorrect results

If you find a bug in puppet-lint or its results, please create an issue in the
[repo issues tracker](https://github.com/floek/puppet-lint-security-plugins/issues/).

## Please contribute

Many other usefull checks may be out there, so feel free to fork and add your own.

## License

The MIT License (MIT)

Copyright (c) 2015 Florian Freund

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
